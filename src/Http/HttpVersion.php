<?php

declare(strict_types=1);

namespace Cloak\Http;

enum HttpVersion: string
{
    case HTTP_1_1 = 'HTTP/1.1';
    case HTTP_2 = 'HTTP/2';
}
