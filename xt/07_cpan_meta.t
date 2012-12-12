use strict;
use warnings;
use Test::More;
use Test::Requires 'Test::CPAN::Meta';

plan skip_all => "There is no META.yml" unless -f "META.yml";

meta_yaml_ok();
