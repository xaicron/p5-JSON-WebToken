use strict;
use warnings FATAL => 'all';
use Module::Build;

my $build = Module::Build->new(
    license              => 'perl',
    recursive_test_files => 1,
    dynamic_config       => 0,
    build_requires       => {
        'Test::Requires'    => '0.06',
        'Test::More'        => '0.98',
        'Test::Mock::Guard' => '0.07'
    },
    configure_requires => { 'Module::Build' => '0.38' },
    requires           => {
        'perl'         => '5.008001',
        'MIME::Base64' => '3.13',
        'Digest::SHA'  => '5.71',
        'Class::Load'  => '0.19',
        'JSON::XS'     => '0',
        'Exporter'     => '5.66',
        'Carp'         => '0'
    },
    no_index    => { 'directory' => [ 'inc', 't', 'xt' ] },
    name        => 'JSON-WebToken',
    module_name => 'JSON::WebToken',

    test_files => ( -d '.git' || $ENV{RELEASE_TESTING} ) ? 't/ xt/' : 't/',

    create_readme  => 1,
    create_license => 1,
);
$build->create_build_script();
