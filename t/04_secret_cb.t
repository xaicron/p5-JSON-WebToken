use strict;
use warnings;
use Test::More;
use JSON::WebToken;

my $secret_map = {
    joe   => "joe's secret",
    smith => "smith's secret",
};

sub test_secret_cb {
    my %specs = @_;
    my ($claims, $desc) = @specs{qw/claims desc/};

    my $secret    = $secret_map->{$claims->{iss}};
    my $secret_cb = sub {
        my ($header, $claims) = @_;
        $secret_map->{$claims->{iss}};
    };

    subtest $desc => sub {
        my $jwt  = encode_jwt $claims, $secret;
        my $data = decode_jwt $jwt, $secret_cb;
        is_deeply $data, $claims;
    };
}

test_secret_cb(
    claims => {
        iss => 'joe',
        exp => time + 30,
        foo => 'bar',
    },
    desc => 'joe',
);

test_secret_cb(
    claims => {
        iss => 'smith',
        exp => time + 30,
        foo => 'bar',
    },
    desc => 'smith',
);

done_testing;
