<?php

declare(strict_types=1);

namespace Cloak\Tls\Enums;

enum ApplicationLayerProtocol: string
{
    case HTTP_1_1 = 'http/1.1';
    case HTTP_2 = 'h2';
}
