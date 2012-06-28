use strict;
use warnings;
use t::Util;

use Test::More;
use Test::Requires 'Crypt::OpenSSL::RSA';

my $rsa = Crypt::OpenSSL::RSA->generate_key(1024);
my $private_key = $rsa->get_private_key_string;
my $public_key  = $rsa->get_public_key_string;

test_encode_decode(
    desc  => 'RS256',
    input => {
        claims     => { foo => 'bar' },
        secret     => $private_key,
        public_key => $public_key,
        algorithm  => 'RS256',
    },
);

test_encode_decode(
    desc  => 'RS384',
    input => {
        claims     => { foo => 'bar' },
        secret     => $private_key,
        public_key => $public_key,
        algorithm  => 'RS384',
    },
);

test_encode_decode(
    desc  => 'RS512',
    input => {
        claims     => { foo => 'bar' },
        secret     => $private_key,
        public_key => $public_key,
        algorithm  => 'RS512',
    },
);

done_testing;
