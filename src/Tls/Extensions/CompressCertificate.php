<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;

class CompressCertificate extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::COMPRESS_CERTIFICATE;

    /**
     * @param int[] $compression_methods
     */
    public function __construct(
        public array $compression_methods,
    ) {}

    /**
     * Create a new instance of CompressCertificate.
     *
     * @param int ...$compression_methods
     */
    public static function make(...$compression_methods): self
    {
        return new self(compression_methods: $compression_methods);
    }

    public function toBytes(): string
    {
        $compression_methods = implode(array_map(fn(int $format) => uint16($format), $this->compression_methods));
        $list = uint8(strlen($compression_methods)) . $compression_methods;

        return uint16($this->extension_type->value) . uint16(strlen($list)) . $list;
    }
}
