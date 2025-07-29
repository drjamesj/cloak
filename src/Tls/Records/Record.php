<?php

declare(strict_types=1);

namespace Cloak\Tls\Records;

use InvalidArgumentException;
use Cloak\Tls\Contracts\HasBytes;
use Cloak\Tls\Data\TLSPlaintext;
use Cloak\Tls\Enums\ContentType;
use Cloak\Tls\Enums\ProtocolVersion;
use Cloak\Tls\Records\ChangeCipherSpec;
use Cloak\Tls\Records\Handshake;

class Record implements HasBytes
{
    public function __construct(
        public ContentType $type,
        public ProtocolVersion $legacy_record_version,
        public TLSPlaintext $fragment,
        public ?string $rawFragment = null,
    ) {
        //
    }

    public static function make(
        ContentType $type,
        ProtocolVersion $legacy_record_version,
        TLSPlaintext $fragment,
    ): self {
        return new self(
            type: $type,
            legacy_record_version: $legacy_record_version,
            fragment: $fragment,
        );
    }

    public function getName(): string
    {
        if ($this->type === ContentType::HANDSHAKE) {
            if ($this->fragment instanceof Handshake) {
                return 'HANDSHAKE: ' . $this->fragment->msg_type->name;
            }
        }

        if ($this->type === ContentType::APPLICATION_DATA) {
            if ($this->fragment instanceof ApplicationData) {
                if ($this->fragment->record instanceof Handshake) {
                    return 'APPLICATION_DATA: HANDSHAKE: ' . $this->fragment->record->msg_type->name;
                } else {
                    return 'APPLICATION_DATA: ' . $this->fragment->innerType->name;
                }
            }
        }

        return match ($this->type) {
            ContentType::HANDSHAKE => 'HANDSHAKE',
            ContentType::CHANGE_CIPHER_SPEC => 'CHANGE_CIPHER_SPEC',
            ContentType::APPLICATION_DATA => 'APPLICATION_DATA',
            default => throw new InvalidArgumentException("Unsupported content type: {$this->type->value}"),
        };
    }

    public function toBytes(): string
    {
        return implode([
            uint8($this->type->value),
            uint16($this->legacy_record_version->value),
            $this->fragment->toBytes(),
        ]);
    }

    public static function fromBytes(
        int $type,
        int $legacy_record_version,
        string $fragment,
        ?string $rawFragment = null,
    ): self {
        $type = ContentType::from($type);

        if ($type === ContentType::HANDSHAKE) {
            return new self(
                type: $type,
                legacy_record_version: ProtocolVersion::from($legacy_record_version),
                fragment: Handshake::fromBytes($fragment),
                rawFragment: $rawFragment,
            );
        } elseif ($type === ContentType::CHANGE_CIPHER_SPEC) {
            return new self(
                type: $type,
                legacy_record_version: ProtocolVersion::from($legacy_record_version),
                fragment: ChangeCipherSpec::fromBytes($fragment),
                rawFragment: $rawFragment,
            );
        } elseif ($type === ContentType::APPLICATION_DATA) {
            return new self(
                type: $type,
                legacy_record_version: ProtocolVersion::from($legacy_record_version),
                fragment: ApplicationData::fromBytes($fragment),
                rawFragment: $rawFragment,
            );
        }

        throw new InvalidArgumentException("Unsupported content type: {$type->value}");
    }
}
