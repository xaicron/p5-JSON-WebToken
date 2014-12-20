use strict;
use warnings;
use t::Util;
use Test::More;
use Test::Mock::Guard qw(mock_guard);

use JSON;

my $expects = join q{}, qw{
    eyJhbGciOiJub25lIn0
    .
    eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
    cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
    .
};

my $header = pack 'C*' => @{ [
    123, 34, 97, 108, 103, 34, 58, 34, 110, 111, 110, 101, 34, 125
] };

my $claims = pack 'C*' => @{ [
    123,  34,  105, 115, 115, 34,  58,  34,  106, 111, 101, 34,  44,  13,
    10,  32,  34,  101, 120, 112, 34,  58,  49,  51,  48,  48,  56,  49,
    57,  51,  56,  48,  44,  13,  10,  32,  34,  104, 116, 116, 112, 58,
    47,  47,  101, 120, 97,  109, 112, 108, 101, 46,  99,  111, 109, 47,
    105, 115, 95,  114, 111, 111, 116, 34,  58,  116, 114, 117, 101, 125
] };

my $secret = '';

my $guard = mock_guard('JSON::WebToken' => {
    encode_json => sub {
        my $array = [$header, $claims];
        sub { shift @$array };
    }->(),
});

my $jwt = JSON::WebToken->encode({}, $secret, 'none');
is $jwt, $expects;

my $data = JSON::WebToken->decode($jwt, $secret, 1, 1);
is_deeply $data, decode_json $claims;

done_testing;
