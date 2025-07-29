<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\GreaseValue;
use Cloak\Tls\Enums\NamedGroup;

class KeyShareEntry
{
    public function __construct(
        public NamedGroup|GreaseValue $group,
        public string $key_exchange,
    ) {
    }

    public static function make(NamedGroup|GreaseValue $group, string $key_exchange): self
    {
        return new self(group: $group, key_exchange: $key_exchange);
    }

    public function toBytes(): string
    {
        return uint16($this->group->value) . uint16(strlen($this->key_exchange)) . $this->key_exchange;
    }
}
