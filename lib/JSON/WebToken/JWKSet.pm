package JSON::WebToken::JWKSet;

use strict;
use warnings;

use JSON;
# local
use JSON::WebToken::JWK;

sub new {
    my $class = shift;
    my $param = {
        _json => JSON->new,
        _set  => {}
    };

    return bless($param, $class);
}

sub parse {
    my ($self, $data) = @_;
    my $json = $self->{'_json'};

    my $set = $json->decode($data);
    # JWK RFC 4.1.  "keys" Parameter
    my $keys = exists $set->{'keys'} ?
        $set->{'keys'} :
        [ $set ];

    for my $single ( @$keys ) {
        my $key = JSON::WebToken::JWK->new($single);
        my $kid = $key->get_param('kid'); # JWK RFC 3.4.  "kid" (Key ID) Parameter

        $self->{'_set'}->{$kid} = $key;
    }
}

sub get_key {
    my $self = shift;
    my $kid  = shift;

    return $self->{'_set'}->{$kid};
}

42;
