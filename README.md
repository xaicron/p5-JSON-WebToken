[![Build Status](https://travis-ci.org/xaicron/p5-JSON-WebToken.svg?branch=master)](https://travis-ci.org/xaicron/p5-JSON-WebToken)
# NAME

JSON::WebToken - JSON Web Token (JWT) implementation

# SYNOPSIS

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

# DESCRIPTION

JSON::WebToken is JSON Web Token (JWT) implementation for Perl

**THIS MODULE IS ALPHA LEVEL INTERFACE.**

# METHODS

## encode($claims \[, $secret, $algorithm, $extra\_headers \]) : String

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

Default encryption algorithm is `HS256`. You can change algorithm as following:

    my $pricate_key_string = '...';
    my $public_key_string  = '...';

    my $jwt = JSON::WebToken->encode({
        iss => 'joe',
        exp => 1300819380,
        'http://example.com/is_root' => JSON::true,
    }, $pricate_key_string, 'RS256');

    my $claims = JSON::WebToken->decode($jwt, $public_key_string);

When you use RS256, RS384 or RS512 algorithm then, We need [Crypt::OpenSSL::RSA](https://metacpan.org/pod/Crypt::OpenSSL::RSA).

If you want to create a `Plaintext JWT`, should be specify `none` for the algorithm.

    my $jwt = JSON::WebToken->encode({
        iss => 'joe',
        exp => 1300819380,
        'http://example.com/is_root' => JSON::true,
    }, '', 'none');
    # $jwt = join '.',
    #     'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0',
    #     'eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ',
    #     ''

## decode($jwt \[, $secret, $verify\_signature, $accepted\_algorithms \]) : HASH

This method is decoding hash reference from JWT string.

    my $claims = JSON::WebToken->decode($jwt, $secret, 1, ["RS256"]);

Any signing algorithm (except "none") is acceptable by default,
so you should check it with $accepted\_algorithms parameter.

## add\_signing\_algorithm($algorithm, $class)

This method is adding signing algorithm.

    # resolve JSON::WebToken::Crypt::MYALG
    JSON::WebToken->add_signing_algorithm('MYALGXXX'   => 'MYALG');

    # resolve Some::Class::Algorithm
    JSON::WebToken->add_signing_algorithm('SOMEALGXXX' => '+Some::Class::Algorithm');

SEE ALSO [JSON::WebToken::Crypt::HMAC](https://metacpan.org/pod/JSON::WebToken::Crypt::HMAC) or [JSON::WebToken::Crypt::RAS](https://metacpan.org/pod/JSON::WebToken::Crypt::RAS).

# FUNCTIONS

## encode\_jwt($claims \[, $secret, $algorithm, $extra\_headers \]) : String

Same as `encode()` method.

## decode\_jwt($jwt \[, $secret, $verify\_signature, $accepted\_algorithms \]) : Hash

Same as `decode()` method.

# ERROR CODES

JSON::WebToken::Exception will be thrown with following code.

## ERROR\_JWT\_INVALID\_PARAMETER

When some method arguments are not valid.

## ERROR\_JWT\_MISSING\_SECRET

When secret is required. (`alg != "none"`)

## ERROR\_JWT\_INVALID\_SEGMENT\_COUNT

When JWT segment count is not between 2 and 4.

## ERROR\_JWT\_INVALID\_SEGMENT\_ENCODING

When each JWT segment is not encoded by base64url.

## ERROR\_JWT\_UNWANTED\_SIGNATURE

When `alg == "none"` but signature segment found.

## ERROR\_JWT\_INVALID\_SIGNATURE

When JWT signature is invalid.

## ERROR\_JWT\_NOT\_SUPPORTED\_SIGNING\_ALGORITHM

When given signing algorithm is not supported.

## ERROR\_JWT\_UNACCEPTABLE\_ALGORITHM

When given signing algorithm is not included in acceptable\_algorithms.

# AUTHOR

xaicron <xaicron@cpan.org>

zentooo

# COPYRIGHT

Copyright 2012 - xaicron

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# SEE ALSO

[http://tools.ietf.org/html/draft-ietf-oauth-json-web-token](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token)
