package JSON::WebToken::Constants;

use strict;
use warnings;
use parent qw/Exporter/;

my @error_code = qw/
    ERROR_JWT_INVALID_PARAMETER
    ERROR_JWT_MISSING_SECRET
    ERROR_JWT_INVALID_SEGMENT_COUNT
    ERROR_JWT_INVALID_SEGMENT_ENCODING
    ERROR_JWT_UNWANTED_SIGNATURE
    ERROR_JWT_INVALID_SIGNATURE
    ERROR_JWT_NOT_SUPPORTED_SIGNING_ALGORITHM
    ERROR_JWK_IS_NOT_DEFINED
    ERROR_JWK_MISSING_FOR_KID
    ERROR_JWT_MISSING_ENCODED_DATA
/;

our @EXPORT = @error_code;
our @EXPORT_OK = ();
our %EXPORT_TAGS = (
    all        => [@EXPORT, @EXPORT_OK],
    error_code => \@error_code,
);

use constant {
    ERROR_JWT_INVALID_PARAMETER               => "invalid_parameter",
    ERROR_JWT_MISSING_SECRET                  => "missing_secret",
    ERROR_JWT_INVALID_SEGMENT_COUNT           => "invalid_segment_count",
    ERROR_JWT_INVALID_SEGMENT_ENCODING        => "invalid_segment_encoding",
    ERROR_JWT_UNWANTED_SIGNATURE              => "unwanted_signature",
    ERROR_JWT_INVALID_SIGNATURE               => "invalid_signature",
    ERROR_JWT_NOT_SUPPORTED_SIGNING_ALGORITHM => "not_supported_signing_algorithm",
    ERROR_JWK_IS_NOT_DEFINED                  => "jwk_is_not_defined",
    ERROR_JWK_MISSING_FOR_KID                 => "missing_for_kid",
    ERROR_JWT_MISSING_ENCODED_DATA            => "missing_encoded_data",
};

1;
__END__
