%% @doc Main module of the eradius application.
-module(eradius).
-export([load_tables/1, load_tables/2,
	 statistics/0, start/0]).

-behaviour(application).
-export([start/2, stop/1, config_change/3]).

%% internal use
-export([error_report/2, info_report/2]).

-include("eradius_lib.hrl").

start() ->
    application:ensure_all_started(eradius).
%% @doc Load RADIUS dictionaries from the default directory.
-spec load_tables(list(eradius_dict:table_name())) -> ok | {error, {consult, eradius_dict:table_name()}}.
load_tables(Tables) ->
    eradius_dict:load_tables(Tables).

%% @doc Load RADIUS dictionaries from a certain directory.
-spec load_tables(file:filename(), list(eradius_dict:table_name())) -> ok | {error, {consult, eradius_dict:table_name()}}.
load_tables(Dir, Tables) ->
    eradius_dict:load_tables(Dir, Tables).



%% @doc get server statistics
statistics() ->
    folsom_metrics:get_metrics_value(eradius).


%% @private
%% @doc Log an error using error_logger
error_report(Fmt, Vals) ->
    error_logger:error_report(lists:flatten(io_lib:format(Fmt, Vals))).

%% @private
%% @doc Log a message using error_logger
info_report(Fmt, Vals) ->
    error_logger:info_report(lists:flatten(io_lib:format(Fmt, Vals))).

%% ----------------------------------------------------------------------------------------------------
%% -- application callbacks

%% @private
start(_StartType, _StartArgs) ->
    eradius_sup:start_link().

%% @private
stop(_State) ->
    ok.

%% @private
config_change(Added, Changed, _Removed) ->
    lists:foreach(fun do_config_change/1, Added),
    lists:foreach(fun do_config_change/1, Changed),
    eradius_client:reconfigure().

do_config_change({tables, NewTables}) ->
    eradius_dict:load_tables(NewTables);
do_config_change({servers, _}) ->
    eradius_server_mon:reconfigure();
do_config_change({_, _}) ->
    ok.
