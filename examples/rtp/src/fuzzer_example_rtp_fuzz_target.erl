-module(fuzzer_example_rtp_fuzz_target).

-behaviour(fuzzer_target).

-export([evaluate/1]).

-type result() :: {ok, non_neg_integer()} | crash.


-spec evaluate(binary()) -> result().
evaluate(Data) ->
    try fuzzer_example_rtp:decode(Data) of
        {ok, Packet} ->
            {ok, success_features(Packet)};
        {error, Reason} ->
            {ok, error_feature(Reason)}
    catch
        _Class:_Reason:_Stacktrace ->
            crash
    end.


-spec success_features(fuzzer_example_rtp:packet()) -> non_neg_integer().
success_features(Packet) ->
    Base = 1 bsl 6,
    WithPadding = feature(maps:get(padding_size, Packet) > 0, 7, Base),
    WithExtension = feature(maps:get(header_extension, Packet) =/= undefined, 8, WithPadding),
    WithCsrc = feature(maps:get(csrcs, Packet) =/= [], 9, WithExtension),
    WithMarker = feature(maps:get(marker, Packet), 10, WithCsrc),
    feature(maps:get(payload, Packet) =:= <<>>, 11, WithMarker).


-spec error_feature(fuzzer_example_rtp:decode_error()) -> non_neg_integer().
error_feature(too_short) ->
    1 bsl 0;
error_feature(unsupported_version) ->
    1 bsl 1;
error_feature(truncated_csrc) ->
    1 bsl 2;
error_feature(truncated_extension_header) ->
    1 bsl 3;
error_feature(truncated_extension_data) ->
    1 bsl 4;
error_feature(invalid_padding) ->
    1 bsl 5.


-spec feature(boolean(), non_neg_integer(), non_neg_integer()) -> non_neg_integer().
feature(true, Bit, Features) ->
    Features bor (1 bsl Bit);
feature(false, _Bit, Features) ->
    Features.
