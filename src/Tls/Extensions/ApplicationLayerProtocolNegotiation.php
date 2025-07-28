<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ApplicationLayerProtocol;
use Cloak\Tls\Enums\ExtensionType;

class ApplicationLayerProtocolNegotiation extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION;

    /**
     * @param \Cloak\Tls\Enums\ApplicationLayerProtocol[] $protocols
     */
    public function __construct(
        public array $protocols,
    ) {}

    /**
     * Create a new instance of ApplicationLayerProtocolNegotiation.
     *
     * @param \Cloak\Tls\Enums\ApplicationLayerProtocol[] $protocols
     */
    public static function make(array $protocols): self
    {
        return new self(protocols: $protocols);
    }

    public function toBytes(): string
    {
        $protocols = implode(array_map(fn(ApplicationLayerProtocol $protocol) => uint8(strlen($protocol->value)) . $protocol->value, $this->protocols));
        $list = uint16(strlen($protocols)) . $protocols;

        return uint16($this->extension_type->value) . uint16(strlen($list)) . $list;
    }
}
