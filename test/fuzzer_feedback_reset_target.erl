%% reset/0 を持つ fuzz target 用のテストモジュール。
%%
%% reset/0 の中でも計測対象の関数を呼び、評価前リセットの経路を通す。
-module(fuzzer_feedback_reset_target).

-behaviour(fuzzer_target).

-export([evaluate/1, reset/0]).


-spec evaluate(binary()) -> {ok, non_neg_integer()} | crash.
evaluate(Data) ->
    case fuzzer_feedback_parser:check(Data) of
        true ->
            crash;
        false ->
            {ok, 0}
    end.


-spec reset() -> ok.
reset() ->
    % reset/0 を持つ target の評価前リセット経路を通すための呼び出し。
    _ = fuzzer_feedback_parser:check(<<"reset">>),
    ok.
