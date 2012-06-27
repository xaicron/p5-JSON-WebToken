package t::Util;

use strict;
use warnings;
use Test::More;
use JSON::WebToken;
use Exporter 'import';

our @EXPORT = qw(test_encode_decode);

sub test_encode_decode {
    my %specs = @_;
    my ($desc, $input, $expects_exception) =
        @specs{qw/desc input expects_exception/};

    my ($claims, $secret, $public_key, $algorithm, $header_fields) =
        @$input{qw/claims secret public_key algorithm header_fields/};
    $public_key ||= $secret;

    my $test = sub {
        my $jwt = encode_jwt $claims, $secret, $algorithm, $header_fields;
        note "jwt: $jwt";
        return decode_jwt $jwt, $public_key, $algorithm;
    };
    subtest $desc => sub {
        unless ($expects_exception) {
            my $got = $test->();
            is_deeply $got, $claims;
        }
        else {
            eval { $test->() };
            like $@, qr/$expects_exception/;
        }
    };
}

1;
__END__
