<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;

class SignedCertificateTimestamp extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP;

    public function __construct()
    {
    }

    public static function make(): self
    {
        return new self();
    }

    public function toBytes(): string
    {
        $payload = '';

        return uint16($this->extension_type->value) . uint16(strlen($payload)) . $payload;
    }
}
