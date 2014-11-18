-module(eradius_example_handler).

-behaviour(eradius_server).
-export([radius_request/3]).

-include_lib("eradius/include/eradius_lib.hrl").
-include_lib("eradius/include/dictionary.hrl").

radius_request(R = #radius_request{cmd = request}, _NasProp, _) ->
    io:format("~nGOT AUTH REQUEST:~n~p~n", [R]),
    User = eradius_lib:get_attr(R, 1),
    io:format("User: ~p~n", [User]),
    case User of
        <<"sdhillon">> ->
            Response = #radius_request{cmd = challenge, attrs = [{?Realm, "lol"}]};
            _ ->
            Response = #radius_request{cmd = accept, attrs = [{?Realm, "foo"}]}
    end,
    {reply, Response};

radius_request(R = #radius_request{cmd = accreq}, _NasProp, _) ->
    io:format("~nGOT ACCT REQUEST:~n~p~n", [R]),
    Response = #radius_request{cmd = accresp, attrs = [{?Menu, <<"foo">>}]},
    {reply, Response}.
