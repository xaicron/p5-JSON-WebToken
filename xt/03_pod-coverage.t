use strict;
use warnings;
use Test::More;
use Test::Requires { 'Test::Pod::Coverage' => 1.04 };

unless ($ENV{TEST_POD_COVERAGE}) {
    plan skip_all => "\$ENV{TEST_POD_COVERAGE} is not set.";
    exit;
}

all_pod_coverage_ok({also_private => [qw(unimport BUILD DEMOLISH)]});
