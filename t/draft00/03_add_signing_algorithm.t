package JSON::WebToken::Crypt::__FOO__;
use Test::More;

sub sign {
    my ($class, $algorithm, $message, $key) = @_;
    return pack 'H*' => join \0, $algorithm, $message, $key;
}

sub verify {
    my ($class, $algorithm, $message, $key, $signature) = @_;
    $signature eq $class->sign($algorithm, $message, $key);
}

package __TEST__::FOO::BAR;

sub sign {
    my ($class, $algorithm, $message, $key) = @_;
    return pack 'H*' => join \0, $algorithm, $message, $key;
}

sub verify {
    my ($class, $algorithm, $message, $key, $signature) = @_;
    $signature eq $class->sign($algorithm, $message, $key);
}

package main;

use strict;
use warnings;
use t::Util;
use Test::More;
use JSON::WebToken::Draft00;

JSON::WebToken::Draft00->add_signing_algorithm(FOO => '__FOO__');

test_encode_decode(
    desc  => 'using JSON::WebToken::Crypt::__FOO__',
    input => {
        claims    => { foo => 'bar' },
        secret    => 'secret',
        algorithm => 'FOO',
    },
);

JSON::WebToken::Draft00->add_signing_algorithm(BAR => '+__TEST__::FOO::BAR');

test_encode_decode(
    desc  => 'using __TEST__::FOO::BAR',
    input => {
        claims    => { foo => 'bar' },
        secret    => 'secret',
        algorithm => 'BAR',
    },
);

done_testing;
