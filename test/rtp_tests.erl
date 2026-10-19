-module(rtp_tests).

-include_lib("eunit/include/eunit.hrl").


minimal_packet_test() ->
    Packet = <<2:2, 0:1, 0:1, 0:4, 0:1, 0:7,
               1:16, 2:32, 3:32, "payload">>,
    ?assertEqual(
      {ok,
       #{
         marker => false,
         payload_type => 0,
         sequence_number => 1,
         timestamp => 2,
         ssrc => 3,
         csrcs => [],
         header_extension => undefined,
         payload => <<"payload">>,
         padding_size => 0
        }},
      fuzzer_example_rtp:decode(Packet)).


csrc_extension_and_padding_test() ->
    Packet = <<2:2, 1:1, 1:1, 1:4, 1:1, 96:7,
               42:16, 1000:32, 16#01020304:32,
               16#05060708:32,
               16#BEDE:16, 1:16, 1, 2, 3, 4,
               "abc", 0, 0, 0, 4>>,
    {ok, Decoded} = fuzzer_example_rtp:decode(Packet),
    ?assertEqual(true, maps:get(marker, Decoded)),
    ?assertEqual(96, maps:get(payload_type, Decoded)),
    ?assertEqual([16#05060708], maps:get(csrcs, Decoded)),
    ?assertEqual(
      #{profile => 16#BEDE, data => <<1, 2, 3, 4>>},
      maps:get(header_extension, Decoded)),
    ?assertEqual(<<"abc">>, maps:get(payload, Decoded)),
    ?assertEqual(4, maps:get(padding_size, Decoded)).


too_short_test() ->
    ?assertEqual({error, too_short}, fuzzer_example_rtp:decode(<<1, 2, 3>>)).


unsupported_version_test() ->
    Packet = <<1:2, 0:1, 0:1, 0:4, 0:1, 0:7, 0:16, 0:32, 0:32>>,
    ?assertEqual({error, unsupported_version}, fuzzer_example_rtp:decode(Packet)).


truncated_csrc_test() ->
    Packet = <<2:2, 0:1, 0:1, 1:4, 0:1, 0:7, 0:16, 0:32, 0:32>>,
    ?assertEqual({error, truncated_csrc}, fuzzer_example_rtp:decode(Packet)).


truncated_extension_header_test() ->
    Packet = <<2:2, 0:1, 1:1, 0:4, 0:1, 0:7, 0:16, 0:32, 0:32>>,
    ?assertEqual({error, truncated_extension_header}, fuzzer_example_rtp:decode(Packet)).


truncated_extension_data_test() ->
    Packet = <<2:2, 0:1, 1:1, 0:4, 0:1, 0:7, 0:16, 0:32, 0:32,
               16#BEDE:16, 1:16>>,
    ?assertEqual({error, truncated_extension_data}, fuzzer_example_rtp:decode(Packet)).


invalid_padding_test() ->
    Packet = <<2:2, 1:1, 0:1, 0:4, 0:1, 0:7, 0:16, 0:32, 0:32, 0>>,
    ?assertEqual({error, invalid_padding}, fuzzer_example_rtp:decode(Packet)).
