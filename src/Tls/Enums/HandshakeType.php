<?php

declare(strict_types=1);

namespace Cloak\Tls\Enums;

use Cloak\Tls\Handshake\Messages\ClientHello;
use InvalidArgumentException;

enum HandshakeType: int
{
    case CLIENT_HELLO = 1;
    case SERVER_HELLO = 2;
    case NEW_SESSION_TICKET = 4;
    case END_OF_EARLY_DATA = 5;
    case ENCRYPTED_EXTENSIONS = 8;
    case CERTIFICATE = 11;
    case CERTIFICATE_REQUEST = 13;
    case CERTIFICATE_VERIFY = 15;
    case FINISHED = 20;
    case KEY_UPDATE = 24;
    case MESSAGE_HASH = 254;

    public static function fromClass(string $class): self
    {
        return match ($class) {
            ClientHello::class => self::CLIENT_HELLO,
            default => throw new InvalidArgumentException("Unknown handshake message class: $class"),
        };
    }
}
