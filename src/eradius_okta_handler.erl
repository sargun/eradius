%%%-------------------------------------------------------------------
%%% @author sdhillon
%%% @copyright (C) 2014, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 18. Nov 2014 6:19 PM
%%%-------------------------------------------------------------------
-module(eradius_okta_handler).
-author("sdhillon").

-behaviour(eradius_server).
-export([radius_request/3]).

-include_lib("eradius/include/eradius_lib.hrl").
-include_lib("eradius/include/dictionary.hrl").

radius_request(Request = #radius_request{cmd = request}, _NasProp, [URLHost, OktaToken]) ->
    lager:debug("Got request: ~p", [Request]),
    Username = eradius_lib:get_attr(Request, ?User_Name),
    Password = eradius_lib:get_attr(Request, ?User_Password),
    case okta_authenticate(Username, Password, URLHost, OktaToken) of
        true ->
            Response = #radius_request{cmd = accept, attrs = []};
        false ->
            Response = #radius_request{cmd = reject, attrs = []}
    end,
    {reply, Response}.

okta_authenticate(Username, Password, URLHost, Token) ->
    [UnpaddedPassword, _] = binary:split(Password, <<0>>),
    Authorization = list_to_binary("SSWS " ++ Token),
    URL = "https://"++URLHost++"/api/v1/authn",
    Headers = [{"Accept", "application/json"},
        {"Content-type", "application/json"},
        {"Authorization", Authorization}],
    Body = jsx:encode([{<<"username">>, Username}, {<<"password">>, UnpaddedPassword}]),
    {ok, Status, ResponseHeaders, ResponseBody} = ibrowse:send_req(URL, Headers, post, Body),
    lager:debug("Okta responded with authentication for: ~s, with {Status, ResponseHeaders, ResponseBody} = ~p", [Username, {Status, ResponseHeaders, ResponseBody}]),
    case Status of
        "200" ->
            true;
        _ ->
            false
    end.


