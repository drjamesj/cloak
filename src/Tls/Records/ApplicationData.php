<?php

declare(strict_types=1);

namespace Cloak\Tls\Records;

use Cloak\Tls\Data\TLSPlaintext;
use Cloak\Tls\Enums\ContentType;
use Cloak\Tls\Traits\CanCreateRecord;
use InvalidArgumentException;

class ApplicationData extends TLSPlaintext
{
    use CanCreateRecord;

    public ContentType $contentType = ContentType::APPLICATION_DATA;

    public function __construct(
        public ContentType $innerType,
        public TLSPlaintext $record,
        public string $raw,
    ) {
        //
    }

    public function toBytes(): string
    {
        return '';
    }

    public static function fromBytes(string $fragment): self
    {
        $innerContentType = ord($fragment[strlen($fragment) - 1]);
        $content = substr($fragment, 0, -1);

        $innerType = ContentType::from($innerContentType);

        $msgLength = unpack('N', "\x00" . substr($content, 1, 3))[1] ?? throw new InvalidArgumentException('Invalid message length in content: ' . bin2hex($content));

        return new self(
            innerType: $innerType,
            record: match ($innerType) {
                ContentType::HANDSHAKE => Handshake::fromBytes($content),
                ContentType::APPLICATION_DATA => new TLSPlaintext($content),
                default => throw new InvalidArgumentException(
                    'Unsupported content type: ' . $innerType->name
                ),
            },
            raw: substr($content, 0, $msgLength + 4),
        );
    }
}
