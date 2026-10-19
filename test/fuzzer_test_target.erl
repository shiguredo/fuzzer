-module(fuzzer_test_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


-spec evaluate(binary()) -> {ok, non_neg_integer()}.
evaluate(Data) ->
    Receiver = whereis(fuzzer_test_receiver),
    true = is_pid(Receiver),
    Receiver ! {fuzzer_test_input, Data},
    {ok, 1}.
