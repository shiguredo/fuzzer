-module(fuzzer_crash_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


-spec evaluate(binary()) -> ok | {ok, non_neg_integer()}.
evaluate(<<>>) ->
    {ok, 1};
evaluate(<<0>>) ->
    {ok, 1};
evaluate(_Data) ->
    erlang:error(target_crash).
