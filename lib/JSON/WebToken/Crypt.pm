package JSON::WebToken::Crypt;

use strict;
use warnings;

sub sign {
    my ($class, $algorithm, $message, $key) = @_;
    die 'sign method must be implements!';
}

sub verify {
    my ($class, $algorithm, $message, $key, $signature) = @_;
    die 'verify method must be implements!'
}

sub sign_with_jwk {
    my ($class, $alg, $msg, $key) = @_;

    $class->sign($alg, $msg, $key->decode_param('k'));
}

sub verify_with_jwk {
    my ($class, $alg, $msg, $key, $sign) = @_;

    return $class->sign($alg, $msg, $key->decode_param('k')) eq $sign;
}

1;
__END__
