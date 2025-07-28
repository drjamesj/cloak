<?php

declare(strict_types=1);

namespace Cloak\Tls\Handshake\Messages;

/**
 * @param \Cloak\Tls\Extensions\BaseExtension[] $extensions
 */
class EncryptedExtensions extends BaseMessage
{
    public function __construct()
    {
        //
    }

    public function toBytes(): string
    {
        return '';
    }

    public static function fromBytes(string $data): self
    {
        return new self();
    }
}
