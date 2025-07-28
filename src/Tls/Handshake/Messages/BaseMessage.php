<?php

declare(strict_types=1);

namespace Cloak\Tls\Handshake\Messages;

use Cloak\Tls\Contracts\HasBytes;
use Cloak\Tls\Enums\HandshakeType;
use Cloak\Tls\Records\Handshake;

abstract class BaseMessage implements HasBytes
{
    public function toHandshake(): Handshake
    {
        return Handshake::make(
            msg_type: HandshakeType::fromClass(static::class),
            msg: $this,
        );
    }
}
