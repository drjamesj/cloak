<?php

declare(strict_types=1);

namespace Cloak\Tls\Traits;

use Cloak\Tls\Records\Record;
use Cloak\Tls\Enums\ProtocolVersion;

trait CanCreateRecord
{
    public function toRecord(): Record
    {
        return new Record(
            type: $this->contentType,
            legacy_record_version: ProtocolVersion::TLS_1_2,
            fragment: $this,
        );
    }
}
