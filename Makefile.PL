use inc::Module::Install;
use Module::Install::AuthorTests;

name 'JSON-WebToken';
all_from 'lib/JSON/WebToken.pm';

requires 'MIME::Base64', '3.13';
requires 'Exporter', '5.66';
requires 'Class::Load', '0.19';
requires 'Digest::SHA', '5.71';
requires 'JSON::XS';
requires 'Carp';

recommends 'Crypt::OpenSSL::RSA', '0.28';

test_requires 'Test::More', '0.98';
test_requires 'Test::Requires', '0.06';
test_requires 'Test::Mock::Guard', '0.07';

tests join q{ }, map { sprintf 't%s.t', '/*' x $_ } 1..3;
author_tests 'xt';

repository 'http://github.com/xaicron/p5-JSON-WebToken/';
bugtracker 'http://github.com/xaicron/p5-JSON-WebToken/issues';

WriteAll;
