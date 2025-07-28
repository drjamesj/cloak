<?php

declare(strict_types=1);

namespace Cloak\Tls\Enums;

enum CipherSuite: int
{
    case TLS_AES_128_GCM_SHA256 = 0x1301;
    case TLS_AES_256_GCM_SHA384 = 0x1302;
    case TLS_CHACHA20_POLY1305_SHA256 = 0x1303;
    case TLS_AES_128_CCM_SHA256 = 0x1304;
    case TLS_AES_128_CCM_8_SHA256 = 0x1305;
}
