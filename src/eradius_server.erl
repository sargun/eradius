%% @doc
%%   This module implements a generic RADIUS server. A handler callback module
%%   is used to process requests. The handler module is selected based on the NAS that
%%   sent the request. Requests from unknown NASs are discarded.
%%
%%   It is also possible to run request handlers on remote nodes. If configured,
%%   the server process will balance load among connected nodes.
%%   Please see the Overview page for a detailed description of the server configuration.
%%
%%   == Callback Description ==
%%
%%   There is only one callback at the moment.
%%
%%   === radius_request(#radius_request{}, #nas_prop{}, HandlerData :: term()) -> {reply, #radius_request{}} | noreply ===
%%
%%   This function is called for every RADIUS request that is received by the server.
%%   Its first argument is a request record which contains the request type and AVPs.
%%   The second argument is a NAS descriptor. The third argument is an opaque term from the
%%   server configuration.
%%
%%   Both records are defined in 'eradius_lib.hrl', but their definition is reproduced here for easy reference.
%%
%%   ```
%%   -record(radius_request, {
%%       reqid         :: byte(),
%%       cmd           :: 'request' | 'accept' | 'challenge' | 'reject' | 'accreq' | 'accresp' | 'coareq' | 'coaack' | 'coanak' | 'discreq' | 'discack' | 'discnak'm
%%       attrs         :: eradius_lib:attribute_list(),
%%       secret        :: eradius_lib:secret(),
%%       authenticator :: eradius_lib:authenticator(),
%%       msg_hmac      :: boolean(),
%%       eap_msg       :: binary()
%%   }).
%%
%%   -record(nas_prop, {
%%       server_ip     :: inet:ip_address(),
%%       server_port   :: eradius_server:port_number(),
%%       nas_ip        :: inet:ip_address(),
%%       nas_port      :: eradius_server:port_number(),
%%       secret        :: eradius_lib:secret(),
%%       trace         :: boolean(),
%%       handler_nodes :: 'local' | list(atom())
%%   }).
%%   '''
-module(eradius_server).
-export([start_link/2, behaviour_info/1]).
-export_type([port_number/0, req_id/0]).

%% internal
-export([do_radius/5, handle_request/3, handle_remote_request/5, stats/2]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include_lib("eradius/include/eradius_lib.hrl").

-define(RESEND_TIMEOUT, 5000).          % how long the binary response is kept after sending it on the socket
-define(RESEND_RETRIES, 3).             % how often a reply may be resent
-define(HANDLER_REPLY_TIMEOUT, 15000).  % how long to wait before a remote handler is considered dead

-type port_number() :: 1..65535.
-type req_id()      :: byte().
-type udp_socket()  :: port().
-type udp_packet()  :: {udp, udp_socket(), inet:ip_address(), port_number(), binary()}.

-record(state, {
    socket                      :: udp_socket(),      % Socket Reference of opened UDP port
    ip = {0,0,0,0}              :: inet:ip_address(), % IP to which this socket is bound
    port = 0                    :: port_number(),     % Port number we are listening on
    transacts = orddict:new()   :: orddict:orddict()          % ETS table containing current transactions
}).

-spec behaviour_info('callbacks') -> [{module(), non_neg_integer()}].
behaviour_info(callbacks) -> [{radius_request,3}].

%% @private
-spec start_link(inet:ip4_address(), port_number()) -> {ok, pid()} | {error, term()}.
start_link(IP = {A,B,C,D}, Port) ->
    Name = list_to_atom(lists:flatten(io_lib:format("eradius_server_~b.~b.~b.~b:~b", [A,B,C,D,Port]))),
    gen_server:start_link({local, Name}, ?MODULE, {IP, Port}, []).

stats(Server, Function) ->
    gen_server:call(Server, {stats, Function}).

%% ------------------------------------------------------------------------------------------
%% -- gen_server Callbacks
%% @private
init({IP, Port}) ->
    process_flag(trap_exit, true),
    case gen_udp:open(Port, [{active, true}, {ip, IP}, binary]) of
        {ok, Socket} ->
            {ok, #state{socket = Socket,
                        ip = IP, port = Port,
                        transacts = orddict:new()}};
        {error, Reason} ->
            {stop, Reason}
    end.

inc_nas_counter(Counter, _NasProp = #nas_prop{server_ip = IP, server_port = Port, nas_ip = NasIP}) ->
    Key = {{{IP, Port}, NasIP}, Counter},
    case folsom_metrics:new_meter(Key) of
        ok ->
            folsom_metrics:tag_metric(Key, eradius),
            folsom_metrics:tag_metric(Key, {IP, Port});
        {error, Key, metric_already_exists} ->
            ok
    end,
    folsom_metrics:notify({Key, 1}).

inc_server_counter(Counter, _State = #state{ip = IP, port = Port}) ->
    Key = {{IP, Port}, Counter},
    case folsom_metrics:new_meter(Key) of
        ok ->
            folsom_metrics:tag_metric(Key, eradius),
            folsom_metrics:tag_metric(Key, {IP, Port});
        {error, Key, metric_already_exists} ->
            ok
    end,
    folsom_metrics:notify({Key, 1}).

%% @private
handle_info(ReqUDP = {udp, Socket, FromIP, FromPortNo, Packet}, State = #state{transacts = Transacts}) ->
    NewState = case lookup_nas(State, FromIP, Packet) of
        {ok, ReqID, Handler, NasProp} ->
            ReqKey = {FromIP, FromPortNo, ReqID},
            NNasProp = NasProp#nas_prop{nas_port = FromPortNo},
            case orddict:find(ReqKey, Transacts) of
                error ->
                    HandlerPid = proc_lib:spawn_link(?MODULE, do_radius, [self(), ReqKey, Handler, NNasProp, ReqUDP]),
                    inc_nas_counter(requests, NasProp),
                    State#state{transacts = orddict:store(ReqKey, {handling, HandlerPid}, Transacts)};
                {handling, _HandlerPid} ->
                    %% handler process is still working on the request
                    dbg(NasProp, "duplicate request (being handled) ~p~n", [ReqKey]),
                    inc_nas_counter(dupRequests, NasProp),
                    State;
                {replied, HandlerPid} ->
                    %% handler process waiting for resend message
                    HandlerPid ! {self(), resend, Socket},
                    dbg(NasProp, "duplicate request (resend) ~p~n", [ReqKey]),
                    inc_nas_counter(dupRequests, NasProp),
                    State
            end;
        {discard, _Reason} ->
            inc_server_counter(invalidRequests, State),
            State
    end,
    {noreply, NewState};
handle_info({replied, ReqKey, HandlerPid}, State = #state{transacts = Transacts}) ->
    NewState = State#state{transacts = orddict:store(ReqKey, {replied, HandlerPid}, Transacts)},
    {noreply, NewState};
handle_info({discarded, ReqKey}, State = #state{transacts = Transacts}) ->
    NewState = State#state{transacts = orddict:erase(ReqKey, Transacts)},
    {noreply, NewState};
handle_info({'EXIT', HandlerPid, _OtherReason}, State = #state{transacts = Transacts}) ->
    Matching = orddict:filter(fun(_ReqKey, {_Status, Pid}) -> Pid == HandlerPid end, Transacts),
    NewState = case orddict:fetch_keys(Matching) of
                   [] ->
                       State;
                   [ReqKey] ->
                       State#state{transacts = orddict:erase(ReqKey, Transacts)}
               end,
    {noreply, NewState};
handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(_Reason, State) ->
    gen_udp:close(State#state.socket),
    ok.

%% @private
handle_call({stats, pull}, _From, State) ->
    io:format("Pulling counters~n", []),
    {reply, 0, State};
handle_call({stats, read}, _From, State) ->
    io:format("Reading counters~n", []),
    {reply, 0, State};
handle_call({stats, reset}, _From, State) ->
    io:format("Resetting counters~n", []),
    {reply, ok, State}.

%% -- unused callbacks
%% @private
handle_cast(_Msg, State)            -> {noreply, State}.
%% @private
code_change(_OldVsn, State, _Extra) -> {ok, State}.

-spec lookup_nas(#state{}, inet:ip_address(), binary()) -> {ok, req_id(), eradius_server_mon:handler(), #nas_prop{}} | {discard, unknown_nas | bad_pdu}.
lookup_nas(#state{ip = IP, port = Port}, NasIP, <<_Code, ReqID, _/binary>>) ->
    case eradius_server_mon:lookup_handler(IP, Port, NasIP) of
        {ok, Handler, NasProp} ->
            {ok, ReqID, Handler, NasProp};
        {error, not_found} ->
            {discard, unknown_nas}
    end;
lookup_nas(_State, _NasIP, _Packet) ->
    {discard, bad_pdu}.

%% ------------------------------------------------------------------------------------------
%% -- Request Handler
%% @private
-spec do_radius(pid(), term(), eradius_server_mon:handler(), #nas_prop{}, udp_packet()) -> any().
do_radius(ServerPid, ReqKey, Handler, NasProp, {udp, Socket, FromIP, FromPort, EncRequest}) ->
    case handle_request(Handler, NasProp, EncRequest) of
        {reply, EncReply} ->
            dbg(NasProp, "sending response for ~p~n", [ReqKey]),
            gen_udp:send(Socket, FromIP, FromPort, EncReply),
            ServerPid ! {replied, ReqKey, self()},
            inc_nas_counter(replies, NasProp),
            {ok, ResendTimeout} = application:get_env(eradius, resend_timeout),
            wait_resend_init(ServerPid, ReqKey, FromIP, FromPort, EncReply, ResendTimeout, ?RESEND_RETRIES);
        {discard, Reason} ->
            dbg(NasProp, "discarding request ~p: ~1000.p~n", [ReqKey, Reason]),
            discard_inc_counter(Reason, NasProp),
            ServerPid ! {discarded, ReqKey};
        {exit, Reason} ->
            dbg(NasProp, "discarding request (handler EXIT) ~p: ~p~n", [ReqKey, Reason]),
            inc_nas_counter(handlerFailure, NasProp),
            ServerPid ! {discarded, ReqKey}
    end.

%% @TODO: extend for other failures
discard_inc_counter(bad_pdu, NasProp) ->
    inc_nas_counter(malformedRequests, NasProp);
discard_inc_counter(_Reason, NasProp) ->
    inc_nas_counter(packetsDropped, NasProp).

wait_resend_init(ServerPid, ReqKey, FromIP, FromPort, EncReply, ResendTimeout, Retries) ->
    erlang:send_after(ResendTimeout, self(), timeout),
    wait_resend(ServerPid, ReqKey, FromIP, FromPort, EncReply, Retries).

wait_resend(ServerPid, ReqKey, _FromIP, _FromPort, _EncReply, 0) ->
    ServerPid ! {discarded, ReqKey};
wait_resend(ServerPid, ReqKey, FromIP, FromPort, EncReply, Retries) ->
    receive
        {ServerPid, resend, Socket} ->
            gen_udp:send(Socket, FromIP, FromPort, EncReply),
            wait_resend(ServerPid, ReqKey, FromIP, FromPort, EncReply, Retries - 1);
        timeout ->
            ServerPid ! {discarded, ReqKey}
    end.


%% @private
-spec handle_request(eradius_server_mon:handler(), #nas_prop{}, binary()) -> any().
handle_request({HandlerMod, HandlerArg}, NasProp, EncRequest) ->
    case eradius_lib:decode_request(EncRequest, NasProp#nas_prop.secret) of
        Request = #radius_request{} ->
            request_inc_counter(Request#radius_request.cmd, NasProp),
            Sender = {NasProp#nas_prop.nas_ip, NasProp#nas_prop.nas_port, Request#radius_request.reqid},
            eradius_log:write_request(Sender, Request),
            apply_handler_mod(HandlerMod, HandlerArg, Request, NasProp);
        bad_pdu ->
            {discard, bad_pdu}
    end.

%% @private
%% @doc this function is spawned on a remote node to handle a radius request.
%%   remote handlers need to be upgraded if the signature of this function changes.
%%   error reports go to the logger of the node that executes the request.
handle_remote_request(ReplyPid, HandlerMod, HandlerArg, NasPropTuple, EncRequest) ->
    group_leader(whereis(user), self()),
    NasProp = nas_prop_tuple_to_record(NasPropTuple),
    Result = handle_request({HandlerMod, HandlerArg}, NasProp, EncRequest),
    ReplyPid ! {self(), Result}.

nas_prop_record_to_tuple(R = #nas_prop{}) ->
    {nas_prop_v1, R#nas_prop.server_ip, R#nas_prop.server_port,
                  R#nas_prop.nas_ip, R#nas_prop.nas_port,
                  R#nas_prop.secret, R#nas_prop.trace}.

nas_prop_tuple_to_record({nas_prop_v1, ServerIP, ServerPort, NasIP, NasPort, Secret, Trace}) ->
    #nas_prop{server_ip = ServerIP, server_port = ServerPort,
              nas_ip = NasIP, nas_port = NasPort,
              secret = Secret, trace = Trace}.

-spec apply_handler_mod(module(), term(), #radius_request{}, #nas_prop{}) -> {discard, term()} | {exit, term()} | {reply, binary()}.
apply_handler_mod(HandlerMod, HandlerArg, Request, NasProp) ->
    try HandlerMod:radius_request(Request, NasProp, HandlerArg) of
        {reply, Reply = #radius_request{cmd = ReplyCmd, attrs = ReplyAttrs, msg_hmac = MsgHMAC, eap_msg = EAPmsg}} ->
            Sender = {NasProp#nas_prop.nas_ip, NasProp#nas_prop.nas_port, Request#radius_request.reqid},
            EncReply = eradius_lib:encode_reply_request(Request#radius_request{cmd = ReplyCmd, attrs = ReplyAttrs,
									       msg_hmac = Request#radius_request.msg_hmac or MsgHMAC or (size(EAPmsg) > 0),
									       eap_msg = EAPmsg}),
            reply_inc_counter(ReplyCmd, NasProp),
            eradius_log:write_request(Sender, Reply),
            {reply, EncReply};
        noreply ->
            {discard, handler_returned_noreply};
        OtherReturn ->
            error_logger:error_report([radius_handler, {type, bad_return},
                                                       {return, OtherReturn}]),
            {discard, {bad_return, OtherReturn}}
    catch
        Class:Reason ->
            error_logger:error_report([radius_handler, {type, 'CRASH'},
                                                       {class, Class},
                                                       {reason, Reason},
                                                       {stacktrace, erlang:get_stacktrace()}]),
            {exit, {Class, Reason}}
    end.

-spec dbg(#nas_prop{}, string(), list()) -> ok.
dbg(#nas_prop{trace = true}, Fmt, Vals) ->
    io:put_chars([printable_date(), " -- ", io_lib:format(Fmt, Vals)]);
dbg(_, _, _) ->
    ok.

-spec printable_date() -> io_lib:chars().
printable_date() ->
    {_ , _, MicroSecs} = Now = now(),
    {{Y, Mo, D}, {H, M, S}} = calendar:now_to_local_time(Now),
    io_lib:format("~4..0b-~2..0b-~2..0b ~2..0b:~2..0b:~2..0b:~4..0b", [Y,Mo,D,H,M,S,MicroSecs div 1000]).


request_inc_counter(request, NasProp) ->
    inc_nas_counter(accessRequests, NasProp);
request_inc_counter(accreq, NasProp) ->
    inc_nas_counter(accountRequests, NasProp);
request_inc_counter(coareq, NasProp) ->
    inc_nas_counter(coaRequests, NasProp);
request_inc_counter(discreq, NasProp) ->
    inc_nas_counter(disconnectRequests, NasProp);
request_inc_counter(_Cmd, _NasProp) ->
    ok.

reply_inc_counter(accept, NasProp) ->
    inc_nas_counter(accessAccepts, NasProp);
reply_inc_counter(reject, NasProp) ->
    inc_nas_counter(accessRejects, NasProp);
reply_inc_counter(challenge, NasProp) ->
    inc_nas_counter(accessChallenges, NasProp);
reply_inc_counter(accresp, NasProp) ->
    inc_nas_counter(accountResponses, NasProp);
reply_inc_counter(coaack, NasProp) ->
    inc_nas_counter(coaAcks, NasProp);
reply_inc_counter(coanak, NasProp) ->
    inc_nas_counter(coaNaks, NasProp);
reply_inc_counter(discack, NasProp) ->
    inc_nas_counter(discAcks, NasProp);
reply_inc_counter(discnak, NasProp) ->
    inc_nas_counter(discNaks, NasProp);
reply_inc_counter(_Cmd, _NasProp) ->
    ok.
