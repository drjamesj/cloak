<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;

class SessionTicket extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::SESSION_TICKET;

    public function __construct(
        public string $data,
    ) {}

    /**
     * Create a new instance of SessionTicket.
     *
     * @param string $data
     */
    public static function make(string $data): self
    {
        return new self(data: $data);
    }

    public function toBytes(): string
    {
        return uint16($this->extension_type->value) . uint16(strlen($this->data)) . $this->data;
    }
}
