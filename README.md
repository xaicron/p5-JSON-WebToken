# NAME

JSON::WebToken - JSON Web Token (JWT) implementation

# SYNOPSIS

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

# DESCRIPTION

JSON::WebToken is JSON Web Token (JWT) implementation for Perl

__THIS MODULE IS ALPHA LEVEL INTERFACE.__

# METHODS

## encode($claims \[, $secret, $algorithm, $extra\_headers \]) : String

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

Default encryption algorithm is `HS256`. You can change algorithm as following:

    my $pricate_key_string = '...';
    my $public_key_string  = '...';

    my $jwt = JSON::WebToken->encode({
        iss => 'joe',
        exp => 1300819380,
        'http://example.com/is_root' => JSON::XS::true,
    }, $pricate_key_string, 'RS256');

    my $claims = JSON::WebToken->decode($jwt, $public_key_string);

When you use RS256, RS384 or RS512 algorithm then, We need [Crypt::OpenSSL::RSA](http://search.cpan.org/perldoc?Crypt::OpenSSL::RSA).

If you want to create a `Plaintext JWT`, should be specify `none` for the algorithm.

    my $jwt = JSON::WebToken->encode({
        iss => 'joe',
        exp => 1300819380,
        'http://example.com/is_root' => JSON::XS::true,
    }, '', 'none');
    # $jwt = join '.',
    #     'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0',
    #     'eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ',
    #     ''

## decode($jwt \[, $secret, $is\_verify \]) : HASH

This method is decoding hash reference from JWT string.

    my $claims = JSON::WebToken->decode($jwt, $secret);

## add\_signing\_algorithm($algorithm, $class)

This method is adding signing algorithm.

    # resolve JSON::WebToken::Crypt::MYALG
    JSON::WebToken->add_signing_algorithm('MYALGXXX'   => 'MYALG');

    # resolve Some::Class::Algorithm
    JSON::WebToken->add_signing_algorithm('SOMEALGXXX' => '+Some::Class::Algorithm');

SEE ALSO [JSON::WebToken::Crypt::HMAC](http://search.cpan.org/perldoc?JSON::WebToken::Crypt::HMAC) or [JSON::WebToken::Crypt::RAS](http://search.cpan.org/perldoc?JSON::WebToken::Crypt::RAS).

# FUNCTIONS

## encode\_jwt($claims \[, $secret, $algorithm, $extra\_headers \]) : String

Same as `encode()` method.

## decode\_jwt($jwt \[, $secret, $is\_verify \]) : Hash

Same as `decode()` method.

# AUTHOR

xaicron <xaicron@cpan.org>

# COPYRIGHT

Copyright 2012 - xaicron

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# SEE ALSO

[http://tools.ietf.org/html/draft-ietf-oauth-json-web-token](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token)
