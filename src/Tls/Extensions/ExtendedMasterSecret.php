<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;

class ExtendedMasterSecret extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::EXTENDED_MASTER_SECRET;

    public function __construct(
        public string $master_secret_data,
        public string $extended_master_secret_data,
    ) {
    }

    /**
     * Create a new instance of ExtendedMasterSecret.
     *
     * @param string $master_secret_data
     * @param string $extended_master_secret_data
     */
    public static function make(string $master_secret_data, string $extended_master_secret_data): self
    {
        return new self(master_secret_data: $master_secret_data, extended_master_secret_data: $extended_master_secret_data);
    }

    public function toBytes(): string
    {
        $payload = '';
        if ($this->master_secret_data) {
            $payload .= uint8(strlen($this->master_secret_data)) . $this->master_secret_data;
        }
        if ($this->extended_master_secret_data) {
            $payload .= uint8(strlen($this->extended_master_secret_data)) . $this->extended_master_secret_data;
        }

        return uint16($this->extension_type->value) . uint16(strlen($payload)) . $payload;
    }
}
