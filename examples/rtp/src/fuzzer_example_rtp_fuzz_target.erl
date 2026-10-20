%% RTP パーサーの fuzz target。
%%
%% feature bitmap は返さない。成功・失敗とエラーの種類はパーサーの行の到達で
%% 区別できるため、Makefile の fuzz-rtp が feedback に fuzzer_example_rtp を
%% 指定して libFuzzer の探索へ渡す。
-module(fuzzer_example_rtp_fuzz_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


-spec evaluate(binary()) -> ok.
evaluate(Data) ->
    % 例外は捕捉せず fuzzer に渡す。クラッシュレポートに理由とスタックトレースが残る。
    % デコード結果は使わない。行の到達は feedback が libFuzzer へ渡す。
    _ = fuzzer_example_rtp:decode(Data),
    ok.
