requires 'Carp';
requires 'Class::Load', '0.19';
requires 'Digest::SHA', '5.71';
requires 'Exporter', '5.59';
requires 'JSON::XS';
requires 'MIME::Base64', '3.13';
requires 'perl', '5.008001';

on build => sub {
    requires 'Test::Mock::Guard', '0.07';
    requires 'Test::More', '0.98';
    requires 'Test::Requires', '0.06';
};
