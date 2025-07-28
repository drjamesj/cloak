<?php

declare(strict_types=1);

namespace Cloak\Tls\Enums;

enum SignatureAlgorithm: int
{
    case RSA_PKCS1_SHA256 = 0x0401;
    case RSA_PKCS1_SHA384 = 0x0501;
    case RSA_PKCS1_SHA512 = 0x0601;

    case ECDSA_SECP256R1_SHA256 = 0x0403;
    case ECDSA_SECP384R1_SHA384 = 0x0503;
    case ECDSA_SECP521R1_SHA512 = 0x0603;

    case RSA_PSS_RSAE_SHA256 = 0x0804;
    case RSA_PSS_RSAE_SHA384 = 0x0805;
    case RSA_PSS_RSAE_SHA512 = 0x0806;

    case ED25519 = 0x0807;
    case ED448 = 0x0808;

    case RSA_PSS_PSS_SHA256 = 0x0809;
    case RSA_PSS_PSS_SHA384 = 0x080A;
    case RSA_PSS_PSS_SHA512 = 0x080B;

    case RSA_PKCS1_SHA1 = 0x0201;
    case ECDSA_SHA1 = 0x0203;
}
