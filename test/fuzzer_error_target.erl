-module(fuzzer_error_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


%% 必ず例外を送出し、クラッシュレポートにスタックトレースが残ることを検証する。
-spec evaluate(binary()) -> {ok, non_neg_integer()} | crash.
evaluate(_Data) ->
    erlang:error(boom).
