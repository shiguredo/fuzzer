-module(fuzzer_crash_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


-spec evaluate(binary()) -> {ok, non_neg_integer()} | crash.
evaluate(<<>>) ->
    {ok, 1};
evaluate(<<0>>) ->
    {ok, 1};
evaluate(_Data) ->
    crash.
