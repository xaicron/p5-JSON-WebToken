use inc::Module::Install;
use Module::Install::AuthorTests;

name 'JSON-WebToken';
all_from 'lib/JSON/WebToken.pm';

#requires '';

test_requires 'Test::More', 0.98;

tests join q{ }, map { sprintf 't%s.t', '/*' x $_ } 1..3;
author_tests 'xt';

repository 'http://github.com/xaicron/p5-JSON-WebToken/';
bugtracker 'http://github.com/xaicron/p5-JSON-WebToken/issues';

WriteAll;
