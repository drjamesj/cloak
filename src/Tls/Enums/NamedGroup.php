<?php

declare(strict_types=1);

namespace Cloak\Tls\Enums;

enum NamedGroup: int
{
    case SECP256R1 = 0x0017;
    case SECP384R1 = 0x0018;
    case SECP521R1 = 0x0019;
    case X25519 = 0x001D;
    case X448 = 0x001E;

    case FFDHE2048 = 0x0100;
    case FFDHE3072 = 0x0101;
    case FFDHE4096 = 0x0102;
    case FFDHE6144 = 0x0103;
    case FFDHE8192 = 0x0104;
}
