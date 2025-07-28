<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;
use Cloak\Tls\Enums\NamedGroup;

class KeyShare extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::KEY_SHARE;

    public function __construct(
        public NamedGroup $group,
        public string $key_exchange,
    ) {}

    public static function make(NamedGroup $group, string $key_exchange): self
    {
        return new self(group: $group, key_exchange: $key_exchange);
    }

    public function toBytes(): string
    {
        $keyShareEntry = uint16($this->group->value) . uint16(strlen($this->key_exchange)) . $this->key_exchange;
        $keyShareList = uint16(strlen($keyShareEntry)) . $keyShareEntry;

        return uint16($this->extension_type->value) . uint16(strlen($keyShareList)) . $keyShareList;
    }

    public static function fromBytes(string $data): self
    {
        return new self(
            group: NamedGroup::from(bytesToInt(takeBytes($data, 2))),
            key_exchange: takeBytes($data, bytesToInt(takeBytes($data, 2))),
        );
    }
}
