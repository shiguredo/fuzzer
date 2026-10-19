-module(fuzzer_example_rtp).

-export([decode/1]).

-type header_extension() :: #{profile := 0..65535, data := binary()}.
-type packet() ::
        #{
          marker := boolean(),
          payload_type := 0..127,
          sequence_number := 0..65535,
          timestamp := 0..4294967295,
          ssrc := 0..4294967295,
          csrcs := [0..4294967295],
          header_extension := undefined | header_extension(),
          payload := binary(),
          padding_size := non_neg_integer()
         }.
-type decode_error() ::
        too_short |
        unsupported_version |
        truncated_csrc |
        truncated_extension_header |
        truncated_extension_data |
        invalid_padding.

-export_type([packet/0, decode_error/0]).


-spec decode(binary()) -> {ok, packet()} | {error, decode_error()}.
decode(<<Version:2, PaddingBit:1, ExtensionBit:1, CsrcCount:4,
         MarkerBit:1, PayloadType:7, SequenceNumber:16,
         Timestamp:32, Ssrc:32, Rest/binary>>) ->
    maybe
        ok ?= validate_version(Version),
        {ok, Csrcs, AfterCsrcs} ?= decode_csrcs(CsrcCount, Rest, []),
        {ok, HeaderExtension, AfterExtension} ?=
            decode_extension(ExtensionBit =:= 1, AfterCsrcs),
        {ok, Payload, PaddingSize} ?=
            decode_padding(PaddingBit =:= 1, AfterExtension),
        {ok,
         #{
           marker => MarkerBit =:= 1,
           payload_type => PayloadType,
           sequence_number => SequenceNumber,
           timestamp => Timestamp,
           ssrc => Ssrc,
           csrcs => Csrcs,
           header_extension => HeaderExtension,
           payload => Payload,
           padding_size => PaddingSize
          }}
    else
        {error, _Reason} = Error ->
            Error
    end;
decode(_Binary) ->
    {error, too_short}.


-spec validate_version(0..3) -> ok | {error, unsupported_version}.
validate_version(2) ->
    ok;
validate_version(_Version) ->
    {error, unsupported_version}.


-spec decode_csrcs(non_neg_integer(), binary(), [non_neg_integer()]) ->
          {ok, [non_neg_integer()], binary()} | {error, truncated_csrc}.
decode_csrcs(0, Rest, Acc) ->
    {ok, lists:reverse(Acc), Rest};
decode_csrcs(Count, <<Csrc:32, Rest/binary>>, Acc) ->
    decode_csrcs(Count - 1, Rest, [Csrc | Acc]);
decode_csrcs(_Count, _Rest, _Acc) ->
    {error, truncated_csrc}.


-spec decode_extension(boolean(), binary()) ->
          {ok, undefined | header_extension(), binary()} |
          {error, truncated_extension_header | truncated_extension_data}.
decode_extension(false, Rest) ->
    {ok, undefined, Rest};
decode_extension(true, <<Profile:16, LengthInWords:16, Rest/binary>>) ->
    Length = LengthInWords * 4,
    case Rest of
        <<Data:Length/binary, Payload/binary>> ->
            {ok, #{profile => Profile, data => Data}, Payload};
        _ ->
            {error, truncated_extension_data}
    end;
decode_extension(true, _Rest) ->
    {error, truncated_extension_header}.


-spec decode_padding(boolean(), binary()) ->
          {ok, binary(), non_neg_integer()} | {error, invalid_padding}.
decode_padding(false, Payload) ->
    {ok, Payload, 0};
decode_padding(true, <<>>) ->
    {error, invalid_padding};
decode_padding(true, PayloadAndPadding) ->
    PaddingSize = binary:last(PayloadAndPadding),
    PayloadAndPaddingSize = byte_size(PayloadAndPadding),
    case PaddingSize > 0 andalso PaddingSize =< PayloadAndPaddingSize of
        true ->
            PayloadSize = PayloadAndPaddingSize - PaddingSize,
            {ok, binary:part(PayloadAndPadding, 0, PayloadSize), PaddingSize};
        false ->
            {error, invalid_padding}
    end.
