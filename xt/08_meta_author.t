use strict;
use warnings;
use Test::More;
use Test::Requires 'Parse::CPAN::Meta';

plan skip_all => "There is no META.yml" unless -f "META.yml";

my $meta = Parse::CPAN::Meta->load_file('META.yml');
isnt $meta->{author}->[0], 'unknown', 'author info';
cmp_ok $meta->{'build_requires'}->{'Test::More'}, '>=', '0.98';
ok $meta->{'requires'}->{'perl'}, 'metayml_declares_perl_version';

done_testing;
