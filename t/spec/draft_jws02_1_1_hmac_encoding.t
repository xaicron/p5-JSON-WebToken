use strict;
use warnings;
use Test::More;
use Test::Mock::Guard qw(mock_guard);
use JSON::XS;
use JSON::WebToken::Draft00;

my $header = pack 'C*' => @{ [
    123, 34, 116, 121, 112, 34, 58, 34, 74,  87,
    84,  34, 44,  13,  10,  32, 34, 97, 108, 103,
    34,  58, 34,  72,  83,  50, 53, 54, 34,  125
] };

my $claims = pack 'C*' => @{ [
    123, 34,  105, 115, 115, 34,  58,  34,  106, 111, 101, 34,  44,  13,
    10,  32,  34,  101, 120, 112, 34,  58,  49,  51,  48,  48,  56,  49,
    57,  51,  56,  48,  44,  13,  10,  32,  34,  104, 116, 116, 112, 58,
    47,  47,  101, 120, 97,  109, 112, 108, 101, 46,  99,  111, 109, 47,
    105, 115, 95,  114, 111, 111, 116, 34,  58,  116, 114, 117, 101, 125
] };

my $secret = pack 'C*' => @{ [
    3,   35,  53,  75,  43,  15,  165, 188, 131, 126, 6,   101, 119, 123,
    166, 143, 90,  179, 40,  230, 240, 84,  201, 40,  169, 15,  132, 178,
    210, 80,  46,  191, 211, 251, 90,  146, 210, 6,   71,  239, 150, 138,
    180, 195, 119, 98,  61,  34,  61,  46,  33,  114, 5,   46,  79,  8,
    192, 205, 154, 245, 103, 208, 128, 163
] };

my $guard = mock_guard('JSON::WebToken::Draft00' => {
    encode_json => sub {
        my $array = [$header, $claims];
        sub { shift @$array };
    }->(),
});

my $jwt = JSON::WebToken::Draft00->encode({}, $secret);
is $jwt, join('.',
    (
        'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
    ),
    (
        'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt'.
        'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
    ),
    (
        'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    ),
);

my $got = JSON::WebToken::Draft00->decode($jwt, $secret);
is_deeply $got, decode_json($claims);

done_testing;
