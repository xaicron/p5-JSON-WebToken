package JSON::WebToken::Crypt::RSA;

use strict;
use warnings;
use parent 'JSON::WebToken::Crypt';

use Crypt::OpenSSL::Bignum;
use Crypt::OpenSSL::RSA ();

our $ALGORITHM2SIGNING_METHOD_MAP = {
    RS256  => 'use_sha256_hash',
    RS384  => 'use_sha384_hash',
    RS512  => 'use_sha512_hash',
    RSA1_5 => 'use_pkcs1_padding',
};

sub sign {
    my ($class, $algorithm, $message, $key) = @_;

    my $private_key = Crypt::OpenSSL::RSA->new_private_key($key);
    my $method = $ALGORITHM2SIGNING_METHOD_MAP->{$algorithm};
    $private_key->$method;
    return $private_key->sign($message);
}

sub verify {
    my ($class, $algorithm, $message, $key, $signature) = @_;

    my $public_key = Crypt::OpenSSL::RSA->new_public_key($key);
    my $method = $ALGORITHM2SIGNING_METHOD_MAP->{$algorithm};
    $public_key->$method;
    return $public_key->verify($message, $signature) ? 1 : 0;
}

sub sign_with_jwk {
    my ($class, $alg, $msg, $key) = @_;

    my @param;
    for my $k ( qw|n e d p q| ) {
        my $val = $key->decode_param($k);
        last unless $val;

        push @param, Crypt::OpenSSL::Bignum->new_from_bin( $val );
    }
    my $crypt  = Crypt::OpenSSL::RSA->new_key_from_parameters(@param);
    my $method = $ALGORITHM2SIGNING_METHOD_MAP->{$alg};

    $crypt->$method;

    return $crypt->sign($msg);
}

sub verify_with_jwk {
    my ($class, $alg, $msg, $key, $sign) = @_;

    my @param;
    for my $k ( qw|n e d p q| ) {
        my $val = $key->decode_param($k);
        last unless $val;

        push @param, Crypt::OpenSSL::Bignum->new_from_bin( $val );
    }
    my $crypt  = Crypt::OpenSSL::RSA->new_key_from_parameters(@param);
    my $method = $ALGORITHM2SIGNING_METHOD_MAP->{$alg};

    $crypt->$method;

    return $crypt->verify($msg, $sign);
}

1;
__END__
