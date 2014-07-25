use strict;
use warnings;

use Test::More;
use JSON::WebToken;

sub KEY_DATA() {
    return <<'EOT';
{
 "keys": [
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "c8cc7d0be76efcaad0cac2b67d9bf04d05ffa3b3",
   "n": "ALjTgs7MwLiBTwbv1YFp4C9LnRl2wzHTAFaIctAYqvqCNSd3CR6qZQYloFckafqjvpWRZve30Dlm9BxuRV27gcdyVvfC/C1qQW3DexxuDWFfm13AJWqWOIJoOv1mYdPdJ+7r9Leasoj3eN38bwLnuvd+jNqHTHzAetP6a+zzmHRV",
   "e": "AQAB"
  },
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "bf3289859b038f80b2bf70bc21fd0520ab274fd3",
   "n": "AL1JGScV3IL+FXaRBDVizMkAWCfecuDRQMt3cuDKG7weLmUYZ/Q0Dk/sGNioHv6I0fMR/wD5GoBB8wwghuhiaobVJvfpYr7HWCrQxxrQWhDwXVPQbtAIPqRtRj2L/c+U0d4lrhuERQoRd2Swx3Nv9flNXQomMzFuLWwX/ZUqA1vv",
   "e": "AQAB"
  },
  {
   "kty":"RSA",
   "q":"xexvbU3YHoS7bBT4skSWlQrM8WoJTltq7R3mLukMTtA4YZ0lzsrtFC68DA1Q7MeXisITP7XkTazVSTd/OIURBepZlAA+vXCyq0JI8siSd+aR0P/yhMGFWHSC0EuLNU4UrERKLPFb7hljSPNoXAy2O2zwOX4rtNXwZ5jWqTKk368=","p":"+e2U2O+czumaiu/JDnMZzgsgKULXFYzGuLH1k3HrI7fCeFX79sG1EluXks0kaGJ8tioyA3Q8OdaRG3QHEh3DawbHe1KKG8I5fDKIzfS6QNpQPbryUY04KKjwugwVw6Si6hQQ0Z1lg1tarYAiMMr4bvPKZa9Uhy58BSXGgkfcErM=","e":"AQAB","d":"kYeqaFAEU/Tehp6kPZeY7yp1VCH0S0bmCWO2Bps2ea2KGEjqoy+8WnkRwNbryIuowMh01dO3Msz/GlY7y+gHeX+rhu/dcIneMD9+G/DQFQMK9PHZc39CPWb3PUv8aZgA0GUXH1x9QLAUmymVnyuQaDAE0XVy2q/BShXFgZpHWpn/ndEQIaihwfg8aauYv1oV1JcNRM8RfrayXDkGxom5JkKvZlMEWjg+dyymZq1E3o7Ow72KyI4q44y+nbIBOi6QxiJMfMNt9CGywAlsy8L5rMB7zCRIcaJhbaYekSmFqL6cScjusmfSFmykKZbszAKCXwIbf3kP7X5Of8k9aUCpxQ==","n":"wTqnWOISdBHKy1j9NKhYiZA2g1lu0NXF8aR55QFr6Nj7GQ0B33OWxGYnf/WcCGYzi68EIpYc3D166+tuWot7dkNbakCi0QBp21xo2N9p1FXoq80vUB6RXCo9+tyB4L+UqZZekqQNSJTb5z2dSMR2Ss1BYiU1olsbE+1Dp48QXjNVWeydA4hk/5AM57PBspBbMgADbxTLz+FzCn0QcjG8msO2Ru/5ePglaBtVoynXSDtQkst4gMBnvUeA3GJxLtqI+tAM0uVI1Kao45aQVGgrveGBZBvXyQlrWklZc2HWHKFs8ti6T3O3Pyi0J1OAtK4kyB51jH09HVCRby51xGa1XQ==",
   "alg":"RS256",
   "kid":"example"
  }
 ]
}
EOT
}

sub JWT() {
    return "eyJhbGciOiJSUzI1NiIsImtpZCI6ImV4YW1wbGUifQ==.eyJhdF9oYXNoIjoic3VlY2llVzBBaEs4QWVjaGllbWFleiIsImF1ZCI6IndvOGFobjhvb2QzdmlmYWlQaGllaHVvY2gyYWhtYWVGYWl4ZXBlTGFraWV5aS5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6MTIzNDU2Nzg5MDA5ODc2NTQzMjEwLCJleHAiOjE0MDU2OTQ4MTUsImVtYWlsIjoiZXhhbXBsZUBleGFtcGxlLmNvbSIsImlhdCI6MTQwNTY5MDkxNSwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzcyI6ImFjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiJ3bzhhaG44b29kM3ZpZmFpUGhpZWh1b2NoMmFobWFlRmFpeGVwZUxha2lleWkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJoZCI6ImV4YW1wbGUuY29tIn0=.diQGbXuSzLh+fnMQc6wbKwwQ4QLkVu1yyex7II7mMfb7PUmsPmmpG7aMT0xXePsl6f+grzmWPtqY5z2Z0n+UV4CxEMM7tYnFb2C8mExIvBXm1skjhdVFKpmbVTkzOuPrNfUO1T9mXZ3uylqKYkVqlg1rwRzvL32ZotKxyU5OwOIh9TDUXhHF+oFtg7jJ9K85euFKqOUPZtaes9KdtaOCAJUyEfZLfuiOTtCNtmuMpY4zK9spm0H/iVNp6gLKUqwjUWbiyUuxmu+DeE0h507OKybMb0JSBIxc9WJ6WlTtuiv2RMTyGR6F5npJdsrOnKtkcud5Ix1yUxPHi4bBqk3GvQ==";
}

subtest 'basic OOP interface' => sub {
    my $jwt = JSON::WebToken->new;

    isa_ok($jwt, 'JSON::WebToken');

    my @methods = qw( set_jwt set_jws header claims encoded verify jwk );
    can_ok($jwt, @methods);

    done_testing;
};

subtest 'jwk' => sub {
    my $jwt = JSON::WebToken->new;

    my $jwk_set = $jwt->jwk(KEY_DATA);
    isa_ok($jwk_set, 'JSON::WebToken::JWKSet');
    can_ok($jwk_set, qw| parse get_key |);

    ok(!$jwk_set->get_key('42'), 'get_key return empty key');

    my $jwk = $jwk_set->get_key('c8cc7d0be76efcaad0cac2b67d9bf04d05ffa3b3');
    isa_ok($jwk, 'JSON::WebToken::JWK');
    can_ok($jwk, qw| get_param decode_param |);

    is($jwk->get_param('alg'), 'RS256', 'get_param returns algorithm');

    my $n = $jwk->get_param('n');
    my $n_decoded = $jwk->decode_param('n');

    ok($n, 'get_param n');
    ok($n_decoded, 'decode_param n');

    isnt($n, $n_decoded, 'decoded not equal to actual value');

    done_testing;
};

subtest 'decode + verify' => sub {
    my $jwt = JSON::WebToken->new;
    my $jwk_set = $jwt->jwk(KEY_DATA);

    eval {
        $jwt->set_jwt(JWT);
    };

    ok(!$@, 'parse successful');
    is($jwt->header('kid'), 'example', 'get kid from header');
    is($jwt->claims('email'), 'example@example.com', 'get email from claims');
    ok($jwt->verify, 'verify successful');

    done_testing;
};

subtest 'encode' => sub {
    my $jwt = JSON::WebToken->new;
    my $jwk_set = $jwt->jwk(KEY_DATA);

    my $header = {
        alg => 'RS256',
        kid => 'test'
    };
    my $claims = {
        iss => 'example.com',
        exp => time,
        aud => 'aaa.example.com'
    };

    $jwt->set_jws($header, $claims);

    eval {
        $jwt->encoded
    };
    ok($@, 'encoded fail due to wrong kid in header');

    $jwt->header(kid => 'example');
    ok($jwt->encoded, 'encoded data');

    done_testing;
};

subtest 'encode + decode + verify' => sub {
    my $jwt = JSON::WebToken->new;
    my $jwk_set = $jwt->jwk(KEY_DATA);

    my $header = {
        alg => 'RS256',
        kid => 'example'
    };
    my $claims = {
        iss   => 'example.com',
        exp   => time,
        aud   => 'aaa.example.com',
        email => 'test@example.com'
    };

    $jwt->set_jws($header, $claims);
    my $token = $jwt->encoded;

    $jwt = JSON::WebToken->new;
    $jwt->jwk(KEY_DATA);

    $jwt->set_jwt($token);

    is_deeply($jwt->claims, $claims, 'claims decrypted successfully');

    done_testing;
};

done_testing;
