package JSON::WebToken::Algorithm;

use strict;
use warnings;

use Class::Load qw(load_class);
# local
use JSON::WebToken::Constants;
use JSON::WebToken::Exception;

our $ALGORITHM_MAP = {
    # for JWS
    HS256  => 'HMAC',
    HS384  => 'HMAC',
    HS512  => 'HMAC',
    RS256  => 'RSA',
    RS384  => 'RSA',
    RS512  => 'RSA',
#    ES256  => 'EC',
#    ES384  => 'EC',
#    ES512  => 'EC',
    none   => 'NONE',

    # for JWE
    RSA1_5           => 'RSA',
#    'RSA-OAEP'       => 'OAEP',
#    A128KW           => '',
#    A256KW           => '',
    dir              => 'NONE',
#    'ECDH-ES'        => '',
#    'ECDH-ES+A128KW' => '',
#    'ECDH-ES+A256KW' => '',

    # for JWK
#    EC  => 'EC',
    RSA => 'RSA',
};

sub get_class {
    my ($class, $algorithm) = @_;

    return $class->_ensure_class_loaded($algorithm);
}

sub add {
    my (undef, $algorithm, $class) = @_;

    $ALGORITHM_MAP->{$algorithm} = $class;
}

my %alg_to_class;
sub _ensure_class_loaded {
    my ($class, $algorithm) = @_;
    return $alg_to_class{$algorithm} if $alg_to_class{$algorithm};

    my $klass = $ALGORITHM_MAP->{$algorithm};
    unless ($klass) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_NOT_SUPPORTED_SIGNING_ALGORITHM,
            message => "`$algorithm` is Not supported siging algorithm",
        );
    }

    my $signing_class = $klass =~ s/^\+// ? $klass : "JSON::WebToken::Crypt::$klass";

    return $alg_to_class{$algorithm} = load_class($signing_class);
}

42;
