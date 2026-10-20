%% フィードバックカバレッジのテスト用 fuzz target。
%%
%% evaluate/1 は常に ok を返し、パーサーが ABC を受け付けたときだけ例外を送出する。
%% feature bitmap には一切情報を入れないため、libFuzzer が ABC を見つけられるかは
%% feedback オプションで渡したコードカバレッジだけに依存する。
-module(fuzzer_feedback_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


-spec evaluate(binary()) -> ok.
evaluate(Data) ->
    case fuzzer_feedback_parser:check(Data) of
        true ->
            erlang:error(abc);
        false ->
            ok
    end.
