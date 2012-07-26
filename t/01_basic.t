use strict;
use warnings;
use t::Util;
use Test::More;

test_encode_decode(
    desc  => 'simple',
    input => {
        claims => { foo => 'bar' },
        secret => 'secret',
    },
);

test_encode_decode(
    desc  => 'with algorithm: HS256',
    input => {
        claims    => { foo => 'bar' },
        secret    => 'secret',
        algorithm => 'HS256',
    },
);

test_encode_decode(
    desc  => 'with algorithm: HS384',
    input => {
        claims    => { foo => 'bar' },
        secret    => 'secret',
        algorithm => 'HS384',
    },
);

test_encode_decode(
    desc  => 'with algorithm: HS512',
    input => {
        claims    => { foo => 'bar' },
        secret    => 'secret',
        algorithm => 'HS512',
    },
);

test_encode_decode(
    desc  => 'with algorithm: none',
    input => {
        claims    => { foo => 'bar' },
        secret    => 'secret',
        algorithm => 'none',
    },
);

test_encode_decode(
    desc  => 'with header_fields',
    input => {
        claims       => { foo => 'bar' },
        secret        => 'secret',
        algorithm     => 'XXXXXX',
        header_fields => {
            alg => 'HS256',
        },
    },
);

done_testing;
