<?php

declare(strict_types=1);

namespace Cloak\Tls\Records;

use Cloak\Tls\Data\TLSPlaintext;
use Cloak\Tls\Enums\ContentType;
use Cloak\Tls\Traits\CanCreateRecord;

class ChangeCipherSpec extends TLSPlaintext
{
    use CanCreateRecord;

    public ContentType $contentType = ContentType::CHANGE_CIPHER_SPEC;

    public function __construct()
    {
        //
    }

    public static function make(): self
    {
        return new self();
    }

    public function toBytes(): string
    {
        return '';
    }

    public static function fromBytes(string $fragment): self
    {
        return new self();
    }
}
