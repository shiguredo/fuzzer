%% フィードバックカバレッジのテスト用パーサー。
%%
%% 先頭から A, B, C の 3 バイトを順に要求する。feature bitmap を一切使わない
%% fuzz target と組み合わせることで、コードカバレッジのフィードバックだけでも
%% 探索が進むことを確認する。
-module(fuzzer_feedback_parser).

-export([check/1]).


-spec check(binary()) -> boolean().
check(<<$A, Rest/binary>>) ->
    check_b(Rest);
check(_Data) ->
    false.


-spec check_b(binary()) -> boolean().
check_b(<<$B, Rest/binary>>) ->
    check_c(Rest);
check_b(_Data) ->
    false.


-spec check_c(binary()) -> boolean().
check_c(<<$C, _Rest/binary>>) ->
    true;
check_c(_Data) ->
    false.
