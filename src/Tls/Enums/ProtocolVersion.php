<?php

declare(strict_types=1);

namespace Cloak\Tls\Enums;

enum ProtocolVersion: int
{
    case TLS_1_2 = 0x0303;
    case TLS_1_3 = 0x0304;
}
