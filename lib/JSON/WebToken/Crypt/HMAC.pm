package JSON::WebToken::Crypt::HMAC;

use strict;
use warnings;
use Carp qw(croak);
use Digest::SHA ();

our $ALGORITHM2SIGNING_METHOD_MAP = {
    HS256 => \&Digest::SHA::hmac_sha256,
    HS384 => \&Digest::SHA::hmac_sha384,
    HS512 => \&Digest::SHA::hmac_sha512,
};

sub sign {
    my ($class, $algorithm, $message, $key) = @_;

    my $sign = '';
    if (my $method = $ALGORITHM2SIGNING_METHOD_MAP->{$algorithm}) {
        $sign = $method->($message, $key);
    }
    else {
        croak "$algorithm is not supported algorithm";
    }

    return $sign;
}

sub verify {
    my ($class, $algorithm, $message, $key, $signature) = @_;
    my $sign = $class->sign($algorithm, $message, $key);
    return $sign eq $signature ? 1 : 0;
}

1;
__END__
