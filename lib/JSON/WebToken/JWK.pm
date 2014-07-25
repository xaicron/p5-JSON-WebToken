package JSON::WebToken::JWK;

use strict;
use warnings;

use JSON::WebToken;

sub new {
    my ($class, $key) = @_;

    return bless($key, $class);
}

sub get_param {
    my ($self, $key) = @_;

    return $self->{$key};
}

sub decode_param {
    my ($self, $key) = @_;

    return unless exists $self->{$key};

    return JSON::WebToken::decode_base64url($self->{$key});
}

42;
