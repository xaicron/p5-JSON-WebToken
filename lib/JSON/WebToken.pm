package JSON::WebToken;

use strict;
use warnings;
use 5.008_001;

our $VERSION = '0.01';

use Exporter 'import';

use Carp qw(croak);
use Class::Load ();
use JSON::XS qw(encode_json decode_json);
use MIME::Base64 qw(encode_base64url decode_base64url);

our @EXPORT = qw(encode_jwt decode_jwt);

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

#our $ENCRIPTION_ALGORITHM_MAP = {
#    'A128CBC+HS256' => 'AES_CBC',
#    'A256CBC+HS512' => 'AES_CBC',
#    A128GCM         => '',
#    A256GCM         => '',
#};

sub encode {
    my ($class, $claims, $secret, $algorithm, $extra_headers) = @_;
    croak 'Usage: JSON::WebToken->encode(\%claims [, $secret, $algorithm, \%$extra_headers ])'
        unless ref $claims eq 'HASH';

    $algorithm     ||= 'HS256';
    $extra_headers ||= {};

    my $header = {
#        typ parameter is OPTIONAL ("JWT" or "urn:ietf:params:oauth:token-type:jwt")
#        typ => 'JWT',
        alg => $algorithm,
        %$extra_headers,
    };

    $algorithm = $header->{alg};
    croak 'secret must be specified' if $algorithm ne 'none' && !defined $secret;

    my $header_segment  = encode_base64url encode_json $header;
    my $claims_segment  = encode_base64url encode_json $claims;
    my $signature_input = join '.', $header_segment, $claims_segment;

    my $signature = $class->_sign($algorithm, $signature_input, $secret);

    return join '.', $signature_input, encode_base64url $signature;
}

sub encode_jwt {
    local $Carp::CarpLevel = $Carp::CarpLevel + 1;
    __PACKAGE__->encode(@_);
}

sub decode {
    my ($class, $jwt, $secret, $is_verify) = @_;
    croak 'Usage: JSON::WebToken->decode($jwt [, $secret, $is_verify ])' unless $jwt;

    $is_verify = 1 unless defined $is_verify;
    croak 'secret must be specified' if $is_verify && !defined $secret;

    my $segments = [ split '\.', $jwt ];
    croak "Not enough or too many segments by $jwt" unless @$segments >= 2 && @$segments <= 4;

    my ($header_segment, $claims_segment, $crypto_segment) = @$segments;
    my $signature_input = join '.', $header_segment, $claims_segment;

    my ($header, $claims, $signature);
    eval {
        $header    = decode_json decode_base64url $header_segment;
        $claims    = decode_json decode_base64url $claims_segment;
        $signature = decode_base64url $crypto_segment if $header->{alg} ne 'none' && $is_verify;
    };
    if (my $e = $@) {
        croak 'Invalid segment encoding';
    }

    return $claims unless $is_verify;

    if (ref $secret eq 'CODE') {
        $secret = $secret->($header, $claims);
    }

    my $algorithm = $header->{alg};
    unless ($class->_verify($algorithm, $signature_input, $secret, $signature)) {
        croak "Invalid signature by $signature";
    }

    return $claims;
}

sub decode_jwt {
    local $Carp::CarpLevel = $Carp::CarpLevel + 1;
    __PACKAGE__->decode(@_);
}

sub add_signing_algorithm {
    my ($class, $algorithm, $signing_class) = @_;
    croak 'Usage: JSON::WebToken->add_signing_algorithm($algorithm, $signing_class)'
        unless $algorithm && $signing_class;
    $ALGORITHM_MAP->{$algorithm} = $signing_class;
}

sub _sign {
    my ($class, $algorithm, $message, $secret) = @_;
    return '' if $algorithm eq 'none';

    local $Carp::CarpLevel = $Carp::CarpLevel + 1;
    $class->_ensure_class_loaded($algorithm)->sign($algorithm, $message, $secret);
}

sub _verify {
    my ($class, $algorithm, $message, $secret, $signature) = @_;
    return 1 if $algorithm eq 'none';

    local $Carp::CarpLevel = $Carp::CarpLevel + 1;
    $class->_ensure_class_loaded($algorithm)->verify($algorithm, $message, $secret, $signature);
}

my (%class_loaded, %alg_to_class);
sub _ensure_class_loaded {
    my ($class, $algorithm) = @_;
    return $alg_to_class{$algorithm} if $alg_to_class{$algorithm};

    my $klass = $ALGORITHM_MAP->{$algorithm};
    unless ($klass) {
        croak "`$algorithm` is Not supported siging algorithm";
    }

    my $signing_class = $klass =~ s/^\+// ? $klass : "JSON::WebToken::Crypt::$klass";
    return $signing_class if $class_loaded{$signing_class};

    Class::Load::load_class($signing_class);

    $class_loaded{$signing_class} = 1;
    $alg_to_class{$algorithm}     = $signing_class;

    return $signing_class;
}

1;
__END__

=encoding utf-8

=for stopwords

=head1 NAME

JSON::WebToken - JSON Web Token (JWT) implementation (draft version 00)

=head1 SYNOPSIS

  use Test::More;
  use JSON::XS;
  use JSON::WebToken;

  my $claims = {
      iss => 'joe',
      exp => 1300819380,
      'http://example.com/is_root' => JSON::XS::true,
  };
  my $secret = 'secret';

  my $jwt = encode_jwt $claims, $secret;
  my $got = decode_jwt $jwt, $secret;
  is_deeply $got, $claims;

  done_testing;

=head1 DESCRIPTION

JSON::WebToken is JSON Web Token (JWT) implementation for Perl

SEE ALSO L<< http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-00 >>

B<< THIS MODULE IS ALPHA LEVEL INTERFACE. >>

=head1 METHODS

=head2 encode($claims [, $secret, $algorithm, $extra_headers ]) : String

This method is encoding JWT from hash reference.

  my $jwt = JSON::WebToken->encode({
      iss => 'joe',
      exp => 1300819380,
      'http://example.com/is_root' => JSON::XS::true,
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
      'http://example.com/is_root' => JSON::XS::true,
  }, $pricate_key_string, 'RS256');

  my $claims = JSON::WebToken->decode($jwt, $public_key_string);

When you use RS256, RS384 or RS512 algorithm then, We need L<< Crypt::OpenSSL::RSA >>.

If you want to create a C<< Plaintext JWT >>, should be specify C<< none >> for the algorithm.

  my $jwt = JSON::WebToken->encode({
      iss => 'joe',
      exp => 1300819380,
      'http://example.com/is_root' => JSON::XS::true,
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

=head1 FUNCTIONS

=head2 encode_jwt($claims [, $secret, $algorithm, $extra_headers ]) : String

Same as C<< encode() >> method.

=head2 decode_jwt($jwt [, $secret, $is_verify ]) : Hash

Same as C<< decode() >> method.

=head1 AUTHOR

xaicron E<lt>xaicron@cpan.orgE<gt>

=head1 COPYRIGHT

Copyright 2012 - xaicron

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

=cut
