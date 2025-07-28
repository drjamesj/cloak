<?php

declare(strict_types=1);

namespace Cloak\Tls\Enums;

enum ExtensionType: int
{
    case SERVER_NAME = 0;
    case MAX_FRAGMENT_LENGTH = 1;
    case STATUS_REQUEST = 5;
    case SUPPORTED_GROUPS = 10;
    case SIGNATURE_ALGORITHMS = 13;
    case USE_SRTP = 14;
    case HEARTBEAT = 15;
    case APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16;
    case SIGNED_CERTIFICATE_TIMESTAMP = 18;
    case CLIENT_CERTIFICATE_TYPE = 19;
    case SERVER_CERTIFICATE_TYPE = 20;
    case PADDING = 21;
    case PRE_SHARED_KEY = 41;
    case EARLY_DATA = 42;
    case SUPPORTED_VERSIONS = 43;
    case COOKIE = 44;
    case PSK_KEY_EXCHANGE_MODES = 45;
    case CERTIFICATE_AUTHORITIES = 47;
    case OID_FILTERS = 48;
    case POST_HANDSHAKE_AUTH = 49;
    case SIGNATURE_ALGORITHMS_CERT = 50;
    case KEY_SHARE = 51;
}
