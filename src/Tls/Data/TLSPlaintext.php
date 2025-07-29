<?php

declare(strict_types=1);

namespace Cloak\Tls\Data;

use Cloak\Tls\Contracts\HasBytes;
use Cloak\Tls\Enums\ContentType;
use Cloak\Tls\Enums\ProtocolVersion;
use Cloak\Tls\Records\Record;

class TLSPlaintext implements HasBytes
{
    public string $data = '';

    public function __construct(
        string $data,
    ) {
        $this->data = $data;
    }

    public function toRecord(): Record
    {
        return Record::make(
            type: ContentType::fromClass(static::class),
            legacy_record_version: ProtocolVersion::TLS_1_2,
            fragment: $this,
        );
    }

    public function toBytes(): string
    {
        return '';
    }
}
