<?php

declare(strict_types=1);

namespace Cloak\Tls\Enums;

use InvalidArgumentException;
use Cloak\Tls\Records\Handshake;

enum ContentType: int
{
    case INVALID = 0;
    case CHANGE_CIPHER_SPEC = 20;
    case ALERT = 21;
    case HANDSHAKE = 22;
    case APPLICATION_DATA = 23;
    case HEARTBEAT = 24;

    public static function fromClass(string $class): self
    {
        return match ($class) {
            Handshake::class => self::HANDSHAKE,
            default => throw new InvalidArgumentException("Unknown content type class: $class"),
        };
    }
}
