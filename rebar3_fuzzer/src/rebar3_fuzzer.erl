-module(rebar3_fuzzer).

-export([init/1]).


-spec init(rebar_state:t()) -> {ok, rebar_state:t()}.
init(State) ->
    {ok, State1} = rebar3_fuzzer_prv:init(State),
    {ok, State1}.
