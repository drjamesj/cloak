<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;
use Cloak\Tls\Enums\NamedGroup;

class KeyShare extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::KEY_SHARE;

    /**
     * @param \Cloak\Tls\Extensions\KeyShareEntry[] $entries
     */
    public function __construct(
        public array $entries,
    ) {}

    /**
     * Create a new instance of KeyShare.
     * 
     * @param \Cloak\Tls\Extensions\KeyShareEntry ...$entries
     */
    public static function make(KeyShareEntry ...$entries): self
    {
        return new self(entries: $entries);
    }

    public function toBytes(): string
    {
        $keyShareList = '';
        foreach ($this->entries as $entry) {
            $keyShareList .= $entry->toBytes();
        }

        $keyShareList = uint16(strlen($keyShareList)) . $keyShareList;

        return uint16($this->extension_type->value) . uint16(strlen($keyShareList)) . $keyShareList;
    }

    public static function fromBytes(string $data): self
    {
        $entries = [];

        while (strlen($data) > 0) {
            $group = NamedGroup::from(bytesToInt(takeBytes($data, 2)));
            $keyExchange = takeBytes($data, bytesToInt(takeBytes($data, 2)));

            $entries[] = KeyShareEntry::make($group, $keyExchange);
        }

        return new self(
            entries: $entries
        );
    }
}
