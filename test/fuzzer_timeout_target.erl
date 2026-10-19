-module(fuzzer_timeout_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


%% 入力タイムアウトの検証用に、必ず 5 秒かかるターゲット。
-spec evaluate(binary()) -> {ok, non_neg_integer()}.
evaluate(_Data) ->
    timer:sleep(5000),
    {ok, 0}.
