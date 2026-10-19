-module(fuzzer_example_sdp_fuzz_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).


-spec evaluate(binary()) -> {ok, non_neg_integer()}.
evaluate(Data) ->
    % 例外は捕捉せず fuzzer に渡す。クラッシュレポートに理由とスタックトレースが残る。
    case fuzzer_example_sdp:decode(Data) of
        {ok, Description} ->
            {ok, success_features(Description)};
        {error, Reason} ->
            {ok, error_feature(Reason)}
    end.


-spec success_features(fuzzer_example_sdp:description()) -> non_neg_integer().
success_features(Description) ->
    Fields = maps:get(fields, Description),
    Base = 1 bsl 7,
    WithConnection = feature(lists:keymember(connection, 1, Fields), 8, Base),
    WithBandwidth = feature(lists:keymember(bandwidth, 1, Fields), 9, WithConnection),
    WithAttribute = feature(lists:keymember(attribute, 1, Fields), 10, WithBandwidth),
    feature(maps:get(media_count, Description) > 0, 11, WithAttribute).


-spec error_feature(fuzzer_example_sdp:decode_error()) -> non_neg_integer().
error_feature(empty) ->
    1 bsl 0;
error_feature(invalid_line_ending) ->
    1 bsl 1;
error_feature(malformed_line) ->
    1 bsl 2;
error_feature(unknown_field) ->
    1 bsl 3;
error_feature(invalid_version) ->
    1 bsl 4;
error_feature(missing_required) ->
    1 bsl 5;
error_feature(missing_timing) ->
    1 bsl 6.


-spec feature(boolean(), non_neg_integer(), non_neg_integer()) -> non_neg_integer().
feature(true, Bit, Features) ->
    Features bor (1 bsl Bit);
feature(false, _Bit, Features) ->
    Features.
