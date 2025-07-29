<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;

class EncryptedClientHello extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::ENCRYPTED_CLIENT_HELLO;

    public function __construct(
        public string $data,
    ) {
    }

    /**
     * Create a new instance of EncryptedClientHello.
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

    public static function makeGrease(): self
    {
        $fakeConfigId = 0; // GREASE-like ID, Chrome/BoringSSL uses 0
        $fakeEnc      = random_bytes(32); // Random bytes for encryption method
        $fakePayload  = random_bytes(rand(
            min: 256,
            max: 511,
        ));

        $ech = uint8($fakeConfigId)
            . uint16(1) . uint16(1) . uint8(175)
            . uint16(strlen($fakeEnc)) . $fakeEnc
            . pack('n', strlen($fakePayload)) . $fakePayload;

        return new self(data: $ech);
    }
}
