package JSON::WebToken::Draft00;

use strict;
use warnings;
use Exporter 'import';

use Carp qw(croak);
use Class::Load ();
use JSON::XS qw(encode_json decode_json);
use MIME::Base64 qw(encode_base64url decode_base64url);

our @EXPORT = qw(encode_jwt decode_jwt);

our $ALGORITHM2SIGNING_CLASS_MAP = {
    HS256 => 'HMAC',
    HS384 => 'HMAC',
    HS512 => 'HMAC',
    RS256 => 'RSA',
    RS384 => 'RSA',
    RS512 => 'RSA',
};

sub encode {
    my ($class, $claims, $key, $algorithm, $header_fields) = @_;
    croak 'Usage: JSON::WebToken->encode(\%claims [, $key, $algorithm, \%$header_fields ])'
        unless ref $claims eq 'HASH';

    $algorithm     ||= 'HS256';
    $header_fields ||= {};

    my $header = {
        typ => 'JWT',
        alg => $algorithm,
        %$header_fields,
    };

    $algorithm = $header->{alg};
    croak 'key must be specified' if $algorithm ne 'none' && !defined $key;

    my $header_segment  = encode_base64url encode_json $header;
    my $claims_segment  = encode_base64url encode_json $claims;
    my $signature_input = join '.', $header_segment, $claims_segment;

    my $signature = $class->_sign($algorithm, $signature_input, $key);

    return join '.', $signature_input, encode_base64url $signature;
}

sub encode_jwt {
    local $Carp::CarpLevel = $Carp::CarpLevel + 1;
    __PACKAGE__->encode(@_);
}

sub decode {
    my ($class, $jwt, $key, $is_verify) = @_;
    croak 'Usage: JSON::WebToken->decode($jwt [, $key, $is_verify ])' unless $jwt;

    $is_verify = 1 unless defined $is_verify;
    croak 'key must be specified' if $is_verify && !defined $key;

    my $segments = [ split '\.', $jwt ];
    croak 'Not enough or too many segments' unless @$segments == 3 || @$segments == 2;

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

    my $algorithm = $header->{alg};
    unless ($class->_verify($algorithm, $signature_input, $key, $signature)) {
        croak 'Invalid signature';
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
    $ALGORITHM2SIGNING_CLASS_MAP->{$algorithm} = $signing_class;
}

sub _sign {
    my ($class, $algorithm, $message, $key) = @_;
    return '' if $algorithm eq 'none';

    local $Carp::CarpLevel = $Carp::CarpLevel + 1;
    $class->_ensure_class_loaded($algorithm)->sign($algorithm, $message, $key);
}

sub _verify {
    my ($class, $algorithm, $message, $key, $signature) = @_;
    return 1 if $algorithm eq 'none';

    local $Carp::CarpLevel = $Carp::CarpLevel + 1;
    $class->_ensure_class_loaded($algorithm)->verify($algorithm, $message, $key, $signature);
}

my %class_loaded;
sub _ensure_class_loaded {
    my ($class, $algorithm) = @_;
    my $klass = $ALGORITHM2SIGNING_CLASS_MAP->{$algorithm};
    unless ($klass) {
        croak "`$algorithm` is Not supported siging algorithm";
    }

    my $signing_class = $klass =~ s/^\+// ? $klass : "JSON::WebToken::Crypt::$klass";
    return $signing_class if $class_loaded{$signing_class};

    Class::Load::load_class($signing_class);
    $class_loaded{$signing_class} = 1;
    return $signing_class;
}

1;
__END__

=encoding utf-8

=for stopwords

=head1 NAME

JSON::WebToken::Draft00 - JSON Web Token (JWT) implementation (draft version 00)

=head1 SYNOPSIS

  use Test::More;
  use JSON::XS;
  use JSON::WebToken;

  my $claims = {
      iss => 'joe',
      exp => 1300819380,
      'http://example.com/is_root' => JSON::XS::true,
  };
  my $key = 'secret';

  my $jwt = encode_jwt $claims, $key;
  my $got = decode_jwt $jwt, $key;
  is_deeply $got, $claims;

  done_testing;

=head1 DESCRIPTION

JSON::WebToken::Draft00 is JSON Web Token (JWT) implementation for Perl

SEE ALSO L<< http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-00 >>

B<< THIS MODULE IS ALPHA LEVEL INTERFACE. >>

=head1 METHODS

=head2 encode($claims [, $key, $algorithm, $header_fields ]) : String

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

=head2 decode($jwt [, $key, $is_verify ]) : HASH

This method is decoding hash reference from JWT string.

  my $claims = JSON::WebToken->decode($jwt, $key);

=head2 add_signing_algorithm($algorithm, $class)

This method is adding singing algorithm.

  # resolve JSON::WebToken::Crypt::MYALG
  JSON::WebToken->add_signing_algorithm('MYALGXXX'   => 'MYALG');

  # resolve Some::Class::Algorithm
  JSON::WebToken->add_signing_algorithm('SOMEALGXXX' => '+Some::Class::Algorithm');

SEE ALSO L<< JSON::WebToken::Crypt::HMAC >> or L<< JSON::WebToken::Crypt::RAS >>.

=head1 FUNCTIONS

=head2 encode_jwt($claims [, $key, $algorithm, $header_fields ]) : String

Same as C<< encode() >> method.

=head2 decode_jwt($jwt [, $key, $is_verify ]) : Hash

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
