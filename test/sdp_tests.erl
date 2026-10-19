-module(sdp_tests).

-include_lib("eunit/include/eunit.hrl").


minimal_description_test() ->
    Data = <<"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Example\r\nt=0 0\r\n">>,
    {ok, Description} = fuzzer_example_sdp:decode(Data),
    ?assertEqual(0, maps:get(version, Description)),
    ?assertEqual(<<"- 1 1 IN IP4 127.0.0.1">>, maps:get(origin, Description)),
    ?assertEqual(<<"Example">>, maps:get(session_name, Description)),
    ?assertEqual(0, maps:get(media_count, Description)).


media_description_test() ->
    Data = <<"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Example\r\n",
             "t=0 0\r\nm=audio 49170 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n">>,
    {ok, Description} = fuzzer_example_sdp:decode(Data),
    ?assertEqual(1, maps:get(media_count, Description)),
    ?assert(lists:keymember(attribute, 1, maps:get(fields, Description))).


empty_test() ->
    ?assertEqual({error, empty}, fuzzer_example_sdp:decode(<<>>)).


invalid_line_ending_test() ->
    ?assertEqual({error, invalid_line_ending}, fuzzer_example_sdp:decode(<<"v=0\n">>)).


malformed_line_test() ->
    ?assertEqual({error, malformed_line}, fuzzer_example_sdp:decode(<<"v=0\r\nbroken\r\n">>)).


unknown_field_test() ->
    ?assertEqual({error, unknown_field}, fuzzer_example_sdp:decode(<<"x=value\r\n">>)).


invalid_version_test() ->
    Data = <<"v=1\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Example\r\nt=0 0\r\n">>,
    ?assertEqual({error, invalid_version}, fuzzer_example_sdp:decode(Data)).


missing_required_test() ->
    ?assertEqual({error, missing_required}, fuzzer_example_sdp:decode(<<"v=0\r\ns=Example\r\nt=0 0\r\n">>)).


missing_timing_test() ->
    Data = <<"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Example\r\n">>,
    ?assertEqual({error, missing_timing}, fuzzer_example_sdp:decode(Data)).
