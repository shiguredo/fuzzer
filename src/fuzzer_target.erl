-module(fuzzer_target).


-callback evaluate(binary()) -> ok | {ok, non_neg_integer()}.
