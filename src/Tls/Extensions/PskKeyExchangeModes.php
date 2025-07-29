<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;

class PskKeyExchangeModes extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::PSK_KEY_EXCHANGE_MODES;

    public function __construct(
        public int $PSK_Key_Exchange_Mode,
    ) {
    }

    /**
     * Create a new instance of PskKeyExchangeModes.
     *
     * @param int $PSK_Key_Exchange_Mode
     */
    public static function make(int $PSK_Key_Exchange_Mode): self
    {
        return new self(PSK_Key_Exchange_Mode: $PSK_Key_Exchange_Mode);
    }

    public function toBytes(): string
    {
        $payload = uint8(0x01) . uint8($this->PSK_Key_Exchange_Mode);

        return uint16($this->extension_type->value) . uint16(strlen($payload)) . $payload;
    }
}
