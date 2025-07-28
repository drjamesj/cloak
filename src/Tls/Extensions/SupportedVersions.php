<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;
use Cloak\Tls\Enums\ProtocolVersion;
use Cloak\Tls\Extensions\BaseExtension;

class SupportedVersions extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::SUPPORTED_VERSIONS;

    /**
     * @param \Cloak\Tls\Enums\ProtocolVersion[] $versions
     */
    public function __construct(
        public array $versions,
    ) {}

    /**
     * Create a new SupportedVersions instance with the given protocol versions.
     *
     * @param \Cloak\Tls\Enums\ProtocolVersion ...$versions
     */
    public static function make(...$versions): self
    {
        return new self(versions: $versions);
    }

    public function toBytes(): string
    {
        $versions = implode(array_map(fn(ProtocolVersion $version) => uint16($version->value), $this->versions));
        $list = uint8(strlen($versions)) . $versions;

        return uint16($this->extension_type->value) . uint16(strlen($list)) . $list;
    }

    public static function fromBytes(string $data): self
    {
        return new self(
            versions: array_map(
                fn($version) => ProtocolVersion::from(bytesToInt($version)),
                str_split($data, 2)
            )
        );
    }
}
