<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;

class ServerName extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::SERVER_NAME;

    public function __construct(
        public string $host_name,
    ) {
    }

    public static function make(string $host_name): self
    {
        return new self($host_name);
    }

    public function toBytes(): string
    {
        $serverNameType = uint8(0x00); // 0x00 for host_name

        $serverName = $serverNameType . uint16(strlen($this->host_name)) . $this->host_name;
        $serverNameList = uint16(strlen($serverName)) . $serverName;

        return uint16($this->extension_type->value) . uint16(strlen($serverNameList)) . $serverNameList;
    }
}
