<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;

class StatusRequest extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::STATUS_REQUEST;

    public function __construct(
        public int $status_type,
        public int $responder_id_list_length,
        public int $request_extensions_length,
    ) {}

    /**
     * Create a new instance of StatusRequest.
     *
     */
    public static function make(): self
    {
        return new self(
            status_type: 1,
            responder_id_list_length: 0,
            request_extensions_length: 0,
        );
    }

    public function toBytes(): string
    {
        $data = '';
        $data .= uint8($this->status_type);
        $data .= uint16($this->responder_id_list_length);
        $data .= uint16($this->request_extensions_length);

        return uint16($this->extension_type->value) . uint16(strlen($data)) . $data;
    }
}
