%% crash_id が target 以外のモジュールのフレームを拾うことを確認する helper。
-module(fuzzer_crash_helper).

-export([boom/0]).


-spec boom() -> no_return().
boom() ->
    erlang:error(helper_boom).
