%% 辞書の自動生成テスト用のモジュール。
-module(fuzzer_dict_sample).

-export([check/1, magic/1, nested/1]).


%% 入れ子の binary の静的な先頭部分を取り出せることを確認するための式。
-spec nested(binary()) -> binary().
nested(Data) ->
    <<16#AA, (<<16#BB, Data/binary>>)/binary>>.


-spec magic(binary()) -> ok | error.
magic(<<"magic", _Rest/binary>>) ->
    ok;
magic(_Data) ->
    error.


-spec check(binary()) -> ok | error.
check(<<Cookie:32, Rest/binary>>) when Cookie =:= 16#2112A442 ->
    check_magic(Rest);
check(<<16#DEADBEEF:32, _Rest/binary>>) ->
    ok;
check(<<16#ABCDEF:24, _Rest/binary>>) ->
    ok;
check(<<"\x89PNG\r\n\x1a\n", _Rest/binary>>) ->
    ok;
check(<<"\xff\xfe", _Rest/binary>>) ->
    ok;
check(_Data) ->
    error.


-spec check_magic(binary()) -> ok | error.
check_magic(<<"magic", _Rest/binary>>) ->
    ok;
check_magic(_Data) ->
    error.
