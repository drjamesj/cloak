<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;
use Cloak\Tls\Enums\SignatureAlgorithm;

class SignatureAlgorithms extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::SIGNATURE_ALGORITHMS;

    /**
     * @param \Cloak\Tls\Enums\SignatureAlgorithm[] $algorithms
     */
    public function __construct(
        public array $algorithms,
    ) {}

    /**
     * Create a new instance of SignatureAlgorithms.
     *
     * @param \Cloak\Tls\Enums\SignatureAlgorithm ...$algorithms
     */
    public static function make(...$algorithms): self
    {
        return new self(algorithms: $algorithms);
    }

    public function toBytes(): string
    {
        $algorithms = implode(array_map(fn(SignatureAlgorithm $algorithm) => uint16($algorithm->value), $this->algorithms));
        $list = uint16(strlen($algorithms)) . $algorithms;

        return uint16($this->extension_type->value) . uint16(strlen($list)) . $list;
    }
}
