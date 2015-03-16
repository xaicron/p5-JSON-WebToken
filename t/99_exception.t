use strict;
use warnings;
use Test::More;
use JSON::WebToken;
use JSON::WebToken::Constants;

subtest 'without claims and secret' => sub {
    eval { encode_jwt };
    like $@, qr/Usage: JSON::WebToken->encode/;
    is $@->code, ERROR_JWT_INVALID_PARAMETER;
};

subtest 'without secret' => sub {
    eval { encode_jwt { foo => 'bar' } };
    like $@, qr/secret must be specified/;
    is $@->code, ERROR_JWT_MISSING_SECRET;
};

subtest 'claims is not HASH' => sub {
    eval { encode_jwt [], 'secret' };
    like $@, qr/Usage: JSON::WebToken->encode/;
    is $@->code, ERROR_JWT_INVALID_PARAMETER;
};

subtest 'not supported algorithm' => sub {
    eval {
        encode_jwt { foo => 'bar' }, 'secret', 'XXXX';
    };
    like $@, qr/`XXXX` is Not supported siging algorithm/;
    is $@->code, ERROR_JWT_NOT_SUPPORTED_SIGNING_ALGORITHM;
};

subtest 'without jwt' => sub {
    eval { decode_jwt };
    like $@, qr/Usage: JSON::WebToken->decode/;
    is $@->code, ERROR_JWT_INVALID_PARAMETER;
};

subtest 'too many segments' => sub {
    eval { decode_jwt 'x.y.z.foo.bar', 'secret' };
    like $@, qr/Not enough or too many segments/;
    is $@->code, ERROR_JWT_INVALID_SEGMENT_COUNT;
};

subtest 'not enough segments' => sub {
    eval { decode_jwt 'x', 'secret' };
    like $@, qr/Not enough or too many segments/;
    is $@->code, ERROR_JWT_INVALID_SEGMENT_COUNT;
};

subtest 'invalid segments' => sub {
    eval { decode_jwt 'x.y.z', 'secret' };
    like $@, qr/Invalid segment encoding/;
    is $@->code, ERROR_JWT_INVALID_SEGMENT_ENCODING;
};

subtest 'invalid signature' => sub {
    my $jwt = encode_jwt { foo => 'bar' }, 'secret';
    eval { decode_jwt "$jwt-xxxx", 'foo' };
    like $@, qr/Invalid signature/;
    is $@->code, ERROR_JWT_INVALID_SIGNATURE;
};

subtest 'unacceptable algorithm' => sub {
    my $jwt = encode_jwt { foo => 'bar' }, '', 'none';
    eval { decode_jwt "$jwt"."xxx", 'foo' };
    like $@, qr/Algorithm "none" is not acceptable/;
    is $@->code, ERROR_JWT_UNACCEPTABLE_ALGORITHM;
};

subtest 'deprecated: accept_algorithm_none' => sub {
    my $jwt = encode_jwt { foo => 'bar' }, '', 'none';
    ok decode_jwt $jwt, "", 1, 1;
    eval { decode_jwt "$jwt", "", 1, 0 };
    like $@, qr/Algorithm "none" is not acceptable/;
    is $@->code, ERROR_JWT_UNACCEPTABLE_ALGORITHM;
};


subtest 'unacceptable algorithm' => sub {
    my $jwt = encode_jwt { foo => 'bar' }, 'secret', 'HS256';
    ok decode_jwt "$jwt", 'secret', 1, ["HS256"];
    ok decode_jwt "$jwt", 'secret', 1, "HS256";
    eval { decode_jwt "$jwt", 'secret', 1, ["RS256"] };
    like $@, qr/Algorithm "HS256" is not acceptable. Followings are accepted:RS256/;
    is $@->code, ERROR_JWT_UNACCEPTABLE_ALGORITHM;


};


subtest 'signature must be empty' => sub {
    my $jwt = encode_jwt { foo => 'bar' }, '', 'none';
    eval { decode_jwt "$jwt"."xxx", 'foo', 1, "none" };
    like $@, qr/Signature must be the empty string when alg is none/;
    is $@->code, ERROR_JWT_UNWANTED_SIGNATURE;
};

subtest 'is_verify true, but without secret' => sub {
    my $jwt = encode_jwt { foo => 'bar' }, 'secret';
    eval { decode_jwt $jwt };
    like $@, qr/secret must be specified/;
    is $@->code, ERROR_JWT_MISSING_SECRET;
};

subtest 'is_verify false' => sub {
    my $jwt = encode_jwt { foo => 'bar' }, 'secret';
    my $got = decode_jwt "$jwt-xxxx", undef, 0;
    is_deeply $got, { foo => 'bar' };
};

done_testing;
