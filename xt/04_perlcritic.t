use strict;
use warnings;
use Test::More;
use Test::Requires { 'Test::Perl::Critic' => 1.02 };

Test::Perl::Critic->import(-profile => 'xt/perlcriticrc');

all_critic_ok('lib');
