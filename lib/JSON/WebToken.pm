package JSON::WebToken;

use strict;
use warnings;
use 5.008_001;

our $VERSION = '0.09';

use parent 'Exporter';

use Carp qw(croak);
use JSON qw(encode_json decode_json);
use MIME::Base64 qw(encode_base64 decode_base64);

use JSON::WebToken::Constants;
use JSON::WebToken::Exception;
use JSON::WebToken::JWKSet;
use JSON::WebToken::Algorithm;

our @EXPORT = qw(encode_jwt decode_jwt);

#our $ENCRIPTION_ALGORITHM_MAP = {
#    'A128CBC+HS256' => 'AES_CBC',
#    'A256CBC+HS512' => 'AES_CBC',
#    A128GCM         => '',
#    A256GCM         => '',
#};

# old interface (working with secret)
sub encode {
    my ($class, $claims, $secret, $algorithm, $extra_headers) = @_;
    unless (ref $claims eq 'HASH') {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_INVALID_PARAMETER,
            message => 'Usage: JSON::WebToken->encode(\%claims [, $secret, $algorithm, \%$extra_headers ])',
        );
    }

    $algorithm     ||= 'HS256';
    $extra_headers ||= {};

    my $header = {
#        typ parameter is OPTIONAL ("JWT" or "urn:ietf:params:oauth:token-type:jwt")
#        typ => 'JWT',
        alg => $algorithm,
        %$extra_headers,
    };

    $algorithm = $header->{alg};
    if ($algorithm ne 'none' && !defined $secret) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_MISSING_SECRET,
            message => 'secret must be specified',
        );
    }

    my $header_segment  = encode_base64url(encode_json $header);
    my $claims_segment  = encode_base64url(encode_json $claims);
    my $signature_input = join '.', $header_segment, $claims_segment;

    my $signature = $class->_sign($algorithm, $signature_input, $secret);

    return join '.', $signature_input, encode_base64url($signature);
}

sub encode_jwt {
    local $Carp::CarpLevel = $Carp::CarpLevel + 1;
    __PACKAGE__->encode(@_);
}

sub decode {
    my ($class, $jwt, $secret, $is_verify) = @_;
    unless (defined $jwt) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_INVALID_PARAMETER,
            message => 'Usage: JSON::WebToken->decode($jwt [, $secret, $is_verify ])',
        );
    }

    $is_verify = 1 unless defined $is_verify;
    if ($is_verify && !defined $secret) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_MISSING_SECRET,
            message => 'secret must be specified',
        );
    }

    my $segments = [ split '\.', $jwt ];
    unless (@$segments >= 2 && @$segments <= 4) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_INVALID_SEGMENT_COUNT,
            message => "Not enough or too many segments by $jwt",
        );
    }

    my ($header_segment, $claims_segment, $crypto_segment) = @$segments;
    my $signature_input = join '.', $header_segment, $claims_segment;

    my ($header, $claims, $signature);
    eval {
        $header    = decode_json decode_base64url($header_segment);
        $claims    = decode_json decode_base64url($claims_segment);
        $signature = decode_base64url($crypto_segment) if $header->{alg} ne 'none' && $is_verify;
    };
    if (my $e = $@) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_INVALID_SEGMENT_ENCODING,
            message => 'Invalid segment encoding',
        );
    }

    return $claims unless $is_verify;

    if (ref $secret eq 'CODE') {
        $secret = $secret->($header, $claims);
    }

    my $algorithm = $header->{alg};
    if ($algorithm eq 'none' and $crypto_segment) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_UNWANTED_SIGNATURE,
            message => 'Signature must be the empty string when alg is none',
        );
    }

    unless ($class->_verify($algorithm, $signature_input, $secret, $signature)) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_INVALID_SIGNATURE,
            message => "Invalid signature by $signature",
        );
    }

    return $claims;
}

sub decode_jwt {
    local $Carp::CarpLevel = $Carp::CarpLevel + 1;
    __PACKAGE__->decode(@_);
}

sub add_signing_algorithm {
    my ($class, $algorithm, $signing_class) = @_;
    unless ($algorithm && $signing_class) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_INVALID_PARAMETER,
            message => 'Usage: JSON::WebToken->add_signing_algorithm($algorithm, $signing_class)',
        );
    }

    JSON::WebToken::Algorithm->add($algorithm, $signing_class);
}

sub _sign {
    my ($class, $algorithm, $message, $secret) = @_;
    return '' if $algorithm eq 'none';

    local $Carp::CarpLevel = $Carp::CarpLevel + 1;
    my $alg_class = JSON::WebToken::Algorithm->get_class($algorithm);
    $alg_class->sign($algorithm, $message, $secret);
}

sub _verify {
    my ($class, $algorithm, $message, $secret, $signature) = @_;
    return 1 if $algorithm eq 'none';

    local $Carp::CarpLevel = $Carp::CarpLevel + 1;
    my $alg_class = JSON::WebToken::Algorithm->get_class($algorithm);
    $alg_class->verify($algorithm, $message, $secret, $signature);
}

# New interface (working with JWK sets)
sub new {
    my $class = shift;
    my $param = {
        _jwt => '',
        _header_dec => {},
        _header_enc => '',
        _claims_dec => {},
        _cliams_enc => '',
        _jwk        => 0, # false
    };

    return bless($param, $class);
}

sub set_jwt {
    my ($self, $jwt) = @_;

    unless (defined $jwt) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_INVALID_PARAMETER,
            message => 'Usage: JSON::WebToken->set_jwt($jwt)',
        );
    }

    $self->{'_jwt'} = $jwt;

    my @segments = split /\./, $jwt;
    $segments[3] = 1; # from_jwt

    $self->set_jws( @segments );
}

sub _decode {
    my ($self, $part) = @_;

    eval {
        $self->{"_${part}_dec"} = decode_json(decode_base64url($self->{"_${part}_enc"}));
    };
    if (my $e = $@) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_INVALID_SEGMENT_ENCODING,
            message => "Invalid segment encoding ($part)",
        );
    }
}

sub set_jws {
    my ($self, $header, $claims, $sign, $from_jwt) = @_;

    unless (defined $header && defined $claims) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_INVALID_PARAMETER,
            message => 'Usage: JSON::WebToken->set_jwt($first, $second, [ $third ])',
        );
    }

    $self->{'_jwt'} = '' unless $from_jwt;
    $self->{'_sign'} = $sign if defined $sign;
    $self->{'_header_dec'} = '';
    $self->{'_header_enc'} = '';
    $self->{'_claims_dec'} = '';
    $self->{'_claims_enc'} = '';

    if (ref($header) eq 'HASH') {
        $self->{'_header_dec'} = $header;
    } else {
        $self->{'_header_enc'} = $header;
    }
    if (ref($claims) eq 'HASH') {
        $self->{'_claims_dec'} = $claims;
    } else {
        $self->{'_claims_enc'} = $claims;
    }
}

sub header {
    my ($self, $key, $value) = @_;

    $self->_decode('header') unless $self->{'_header_dec'};

    unless (defined $key) {
        return $self->{'_header_dec'};
    }

    unless (defined $value) {
        return $self->{'_header_dec'}->{$key};
    }

    $self->{'_jwt'} = '';
    $self->{'_header_enc'} = '';
    $self->{'_header_dec'}->{$key} = $value;
}

sub claims {
    my ($self, $key, $value) = @_;

    $self->_decode('claims') unless $self->{'_claims_dec'};

    unless (defined $key) {
        return $self->{'_claims_dec'};
    }

    unless (defined $value) {
        return $self->{'_claims_dec'}->{$key};
    }

    $self->{'_jwt'} = '';
    $self->{'_claims_enc'} = '';
    $self->{'_claims_dec'}->{$key} = $value;
}

sub _encode {
    my $self = shift;
    my $jwk  = $self->{'_jwk'};

    unless ($jwk) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWK_IS_NOT_DEFINED,
            message => 'JWK is not defined. Define it with JSON::WebToken->jwk($json)',
        );
    }

    $self->{'_header_enc'} = encode_base64url(encode_json($self->{'_header_dec'}), '');
    $self->{'_claims_enc'} = encode_base64url(encode_json($self->{'_claims_dec'}), '');

    my $for_sig = $self->{'_header_enc'} .'.'. $self->{'_claims_enc'};
    $self->{'_jwt'} = $for_sig .'.';

    my $alg = $self->header('alg');
    return if $alg eq 'none';

    my $kid = $self->header('kid');
    my $key = $jwk->get_key($kid);

    unless ($key) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWK_MISSING_FOR_KID,
            message => 'There are no JWK for given KID',
        );
    }

    my $alg_class = JSON::WebToken::Algorithm->get_class($alg);
    $self->{'_jwt'} .= encode_base64url($alg_class->sign_with_jwk($alg, $for_sig, $key), '');
}

sub encoded {
    my $self = shift;

    $self->_encode unless $self->{'_jwt'};

    return $self->{'_jwt'};
}

sub verify {
    my $self = shift;
    my $jwk  = $self->{'_jwk'};

    unless ($jwk) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWK_IS_NOT_DEFINED,
            message => 'JWK is not defined. Define it with JSON::WebToken->jwk($json)',
        );
    }

    my $kid = $self->header('kid');
    my $key = $jwk->get_key($kid);

    unless ($key) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWK_MISSING_FOR_KID,
            message => 'There are no JWK for given KID',
        );
    }

    unless ($self->{'_header_enc'} && $self->{'_claims_enc'}) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_MISSING_ENCODED_DATA,
            message => 'There are not encoded header and claims',
        );
    }

    my $for_sig = $self->{'_header_enc'} .'.'. $self->{'_claims_enc'};
    my $alg = $self->header('alg');
    my $sign_dec = decode_base64url($self->{'_sign'});

    my $alg_class = JSON::WebToken::Algorithm->get_class($alg);
    return $alg_class->verify_with_jwk($alg, $for_sig, $key, $sign_dec);
}

sub jwk {
    my ($self, $data) = @_;
    my $jwk_set = JSON::WebToken::JWKSet->new;

    unless (defined $data) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_INVALID_PARAMETER,
            message => 'Usage: JSON::WebToken->jwk($json)',
        );
    }

    eval {
        $jwk_set->parse($data);
    };
    if (my $err = $@) {
        JSON::WebToken::Exception->throw(
            code    => ERROR_JWT_INVALID_PARAMETER,
            message => 'Invalid JWK, should be in JSON format',
        );
    }

    $self->{'_jwk'} = $jwk_set;
}

####################################################
# Taken from newer MIME::Base64
# In order to support older version of MIME::Base64
####################################################
sub encode_base64url {
    my $e = encode_base64(shift, "");
    $e =~ s/=+\z//;
    $e =~ tr[+/][-_];
    return $e;
}

sub decode_base64url {
    my $s = shift;
    $s =~ tr[-_][+/];
    $s .= '=' while length($s) % 4;
    return decode_base64($s);
}

1;
__END__

=encoding utf-8

=for stopwords

=head1 NAME

JSON::WebToken - JSON Web Token (JWT) implementation

=head1 SYNOPSIS

  use Test::More;
  use JSON;
  use JSON::WebToken;

  my $claims = {
      iss => 'joe',
      exp => 1300819380,
      'http://example.com/is_root' => JSON::true,
  };
  my $secret = 'secret';

  my $jwt = encode_jwt $claims, $secret;
  my $got = decode_jwt $jwt, $secret;
  is_deeply $got, $claims;

  done_testing;

=head1 DESCRIPTION

JSON::WebToken is JSON Web Token (JWT) implementation for Perl

B<< THIS MODULE IS ALPHA LEVEL INTERFACE. >>

=head1 METHODS

=head2 encode($claims [, $secret, $algorithm, $extra_headers ]) : String

This method is encoding JWT from hash reference.

  my $jwt = JSON::WebToken->encode({
      iss => 'joe',
      exp => 1300819380,
      'http://example.com/is_root' => JSON::true,
  }, 'secret');
  # $jwt = join '.',
  #     'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  #     'eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ'
  #     '4ldFxjibgJGz_uaIRCIq89b5ipR-sbI2Uq7B2WNEDs0'

Default encryption algorithm is C<< HS256 >>. You can change algorithm as following:

  my $pricate_key_string = '...';
  my $public_key_string  = '...';

  my $jwt = JSON::WebToken->encode({
      iss => 'joe',
      exp => 1300819380,
      'http://example.com/is_root' => JSON::true,
  }, $pricate_key_string, 'RS256');

  my $claims = JSON::WebToken->decode($jwt, $public_key_string);

When you use RS256, RS384 or RS512 algorithm then, We need L<< Crypt::OpenSSL::RSA >>.

If you want to create a C<< Plaintext JWT >>, should be specify C<< none >> for the algorithm.

  my $jwt = JSON::WebToken->encode({
      iss => 'joe',
      exp => 1300819380,
      'http://example.com/is_root' => JSON::true,
  }, '', 'none');
  # $jwt = join '.',
  #     'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0',
  #     'eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ',
  #     ''

=head2 decode($jwt [, $secret, $is_verify ]) : HASH

This method is decoding hash reference from JWT string.

  my $claims = JSON::WebToken->decode($jwt, $secret);

=head2 add_signing_algorithm($algorithm, $class)

This method is adding signing algorithm.

  # resolve JSON::WebToken::Crypt::MYALG
  JSON::WebToken->add_signing_algorithm('MYALGXXX'   => 'MYALG');

  # resolve Some::Class::Algorithm
  JSON::WebToken->add_signing_algorithm('SOMEALGXXX' => '+Some::Class::Algorithm');

SEE ALSO L<< JSON::WebToken::Crypt::HMAC >> or L<< JSON::WebToken::Crypt::RAS >>.

=head2 new()

Default constructor for OOP interface. Does not need any additional parameter to be passed into.

e.g.

  my $jwt = JSON::WebToken->new;

=head2 set_jwt($jwt)

Accepts JWT defined in L<< http://tools.ietf.org/html/draft-jones-json-web-token-10 >> and sets internal variables. Does not return anything.

Trig exception only if no C<< $jwt >> is passed.

e.g.

  $jwt->set_jwt("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

=head2 set_jws($header, $claims, [ $signature ])

Accepts 3 JWS parameters in different formats. This method sets internal variables for future use.

e.g.

  # for decoding purposes
  $jwt->set_jws("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9", "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

  # for encoding purposes
  $jwt->set_jws({kid => "example", alg => 'RS256'}, {iss => 'example.com});

=head2 header([$key, [ $value ]])

Method to manipulate with header data. This method transparently decode data if needed. ERROR_JWT_INVALID_SEGMENT_ENCODING - exception will be raised if decode will fail.

e.g.
  # without any paramters return header as a hash reference
  my $header = $jwt->header;

  # or you can get value via $key
  my $kid = $jwt->header('kid');

  # or you can set value
  $jwt->header('alg' => 'RS256');

=head2 claims([$key, [ $value ]])

Method to manipulate with claims data. This method transparently decode data if needed. ERROR_JWT_INVALID_SEGMENT_ENCODING - exception will be raised if decode will fail.

e.g.

  # get all claims hash
  my $claims = $jwt->claims;

  # get by $key
  my $email = $jwt->claims('email');

  # set value
  $jwt->claims('email' => 'example@example.com');

=head2 encoded()

Returns JWT string in a format acceptable by method C<< set_jws() >>. Transparently encode JWT. ERROR_JWK_IS_NOT_DEFINED or ERROR_JWK_MISSING_FOR_KID can be raised.

e.g.

  my $jwt_string = $jwt->encoded;

=head2 verify()

Verifies signature of JWT. The following list of exceptions can be triggered: ERROR_JWK_IS_NOT_DEFINED, ERROR_JWK_MISSING_FOR_KID, ERROR_JWT_MISSING_ENCODED_DATA.

e.g.

  if ($jwt->verify) {
      print "Verified";
  }

=head2 jwk( $data )

Accepts $data as a json string. Parse json JWK and sets internal variables. Can accept 1 key or set of keys (JWK Sets).

e.g.

  $jwt->jwk({ "kty":"oct", "alg":"A128KW", "k":"GawgguFyGrWKav7AX4VKUg" });

=head1 FUNCTIONS

=head2 encode_jwt($claims [, $secret, $algorithm, $extra_headers ]) : String

Same as C<< encode() >> method.

=head2 decode_jwt($jwt [, $secret, $is_verify ]) : Hash

Same as C<< decode() >> method.

=head1 ERROR CODES

JSON::WebToken::Exception will be thrown with following code.

=head2 ERROR_JWT_INVALID_PARAMETER

When some method arguments are not valid.

=head2 ERROR_JWT_MISSING_SECRET

When secret is required. (C<< alg != "none" >>)

=head2 ERROR_JWT_INVALID_SEGMENT_COUNT

When JWT segment count is not between 2 and 4.

=head2 ERROR_JWT_INVALID_SEGMENT_ENCODING

When each JWT segment is not encoded by base64url.

=head2 ERROR_JWT_UNWANTED_SIGNATURE

When C<< alg == "none" >> but signature segment found.

=head2 ERROR_JWT_INVALID_SIGNATURE

When JWT signature is invalid.

=head2 ERROR_JWT_NOT_SUPPORTED_SIGNING_ALGORITHM

When given signing algorithm is not supported.

=head2 ERROR_JWK_IS_NOT_DEFINED

When you try to encode/decode data without defining JWK via method C<< jwk() >>

=head2 ERROR_JWK_MISSING_FOR_KID

When you JWK could not be found by provided KID in header.

=head2 ERROR_JWT_MISSING_ENCODED_DATA

When you try to verify data which are not encoded.

=head1 AUTHOR

xaicron E<lt>xaicron@cpan.orgE<gt>

zentooo

cono E<lt>cono@cpan.orgE<gt>

=head1 COPYRIGHT

Copyright 2014 - xaicron

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

L<< http://tools.ietf.org/html/draft-ietf-oauth-json-web-token >>

L<< http://tools.ietf.org/html/draft-ietf-jose-json-web-key-31 >>

L<< http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-16 >>

=cut
