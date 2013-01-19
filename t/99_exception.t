use strict;
use warnings;
use Test::More;
use JSON::WebToken;

subtest 'without claims and secret' => sub {
    eval { encode_jwt };
    like $@, qr/Usage: JSON::WebToken->encode/;
};

subtest 'without secret' => sub {
    eval { encode_jwt { foo => 'bar' } };
    like $@, qr/secret must be specified/;
};

subtest 'claims is not HASH' => sub {
    eval { encode_jwt [], 'secret' };
    like $@, qr/Usage: JSON::WebToken->encode/;
};

subtest 'not supported algorithm' => sub {
    eval {
        encode_jwt { foo => 'bar' }, 'secret', 'XXXX';
    };
    like $@, qr/`XXXX` is Not supported siging algorithm/;
};

subtest 'without jwt' => sub {
    eval { decode_jwt };
    like $@, qr/Usage: JSON::WebToken->decode/;
};

subtest 'too many segments' => sub {
    eval { decode_jwt 'x.y.z.foo.bar', 'secret' };
    like $@, qr/Not enough or too many segments/;
};

subtest 'not enough segments' => sub {
    eval { decode_jwt 'x', 'secret' };
    like $@, qr/Not enough or too many segments/;
};

subtest 'invalid segments' => sub {
    eval { decode_jwt 'x.y.z', 'secret' };
    like $@, qr/Invalid segment encoding/;
};

subtest 'invalid signature' => sub {
    my $jwt = encode_jwt { foo => 'bar' }, 'secret';
    eval { decode_jwt "$jwt-xxxx", 'foo' };
    like $@, qr/Invalid signature/;
};

subtest 'is_verify true, but without secret' => sub {
    my $jwt = encode_jwt { foo => 'bar' }, 'secret';
    eval { decode_jwt $jwt };
    like $@, qr/secret must be specified/;
};

subtest 'is_verify false' => sub {
    my $jwt = encode_jwt { foo => 'bar' }, 'secret';
    my $got = decode_jwt "$jwt-xxxx", undef, 0;
    is_deeply $got, { foo => 'bar' };
};

done_testing;
