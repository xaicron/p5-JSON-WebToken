package JSON::WebToken::Crypt::HMAC;

use strict;
use warnings;
use Carp qw(croak);
use Digest::SHA ();

sub sign {
    my ($class, $algorithm, $message, $key) = @_;

    my $sign = '';
    if ($algorithm eq 'HS256') {
        $sign = Digest::SHA::hmac_sha256($message, $key);
    }
    elsif ($algorithm eq 'HS384') {
        $sign = Digest::SHA::hmac_sha384($message, $key);
    }
    elsif ($algorithm eq 'HS512') {
        $sign = Digest::SHA::hmac_sha512($message, $key);
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
