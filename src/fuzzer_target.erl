-module(fuzzer_target).


-callback evaluate(binary()) -> {ok, non_neg_integer()} | crash.
