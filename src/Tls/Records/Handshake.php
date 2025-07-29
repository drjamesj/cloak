<?php

declare(strict_types=1);

namespace Cloak\Tls\Records;

use Cloak\Tls\Data\TLSPlaintext;
use InvalidArgumentException;
use Cloak\Tls\Handshake\Messages\BaseMessage;
use Cloak\Tls\Handshake\Messages\ClientHello;
use Cloak\Tls\Handshake\Messages\ServerHello;
use Cloak\Tls\Enums\ContentType;
use Cloak\Tls\Enums\HandshakeType;
use Cloak\Tls\Handshake\Messages\Certificate;
use Cloak\Tls\Handshake\Messages\CertificateVerify;
use Cloak\Tls\Handshake\Messages\EncryptedExtensions;
use Cloak\Tls\Handshake\Messages\Finished;
use Cloak\Tls\Handshake\Messages\NewSessionTicket;
use Cloak\Tls\Traits\CanCreateRecord;

class Handshake extends TLSPlaintext
{
    use CanCreateRecord;

    public ContentType $contentType = ContentType::HANDSHAKE;

    public function __construct(
        public HandshakeType $msg_type,
        public BaseMessage $msg,
    ) {
        //
    }

    public static function make(
        HandshakeType $msg_type,
        BaseMessage $msg,
    ): self {
        return new self(msg_type: $msg_type, msg: $msg);
    }

    public function toBytes(): string
    {
        $msg = $this->msg->toBytes();

        return uint16(strlen($msg)) . $msg;
    }

    public static function fromBytes(string $fragment): self
    {
        $type = HandshakeType::from(ord($fragment[0]));

        return new self(
            msg_type: $type,
            msg: match ($type) {
                HandshakeType::SERVER_HELLO => ServerHello::fromBytes(substr($fragment, 4)),
                HandshakeType::ENCRYPTED_EXTENSIONS => EncryptedExtensions::fromBytes(substr($fragment, 4)),
                HandshakeType::CERTIFICATE => Certificate::fromBytes(substr($fragment, 4)),
                HandshakeType::CERTIFICATE_VERIFY => CertificateVerify::fromBytes(substr($fragment, 4)),
                HandshakeType::NEW_SESSION_TICKET => NewSessionTicket::fromBytes(substr($fragment, 4)),
                HandshakeType::FINISHED => Finished::fromBytes(substr($fragment, 4)),
                default => throw new InvalidArgumentException("Unsupported handshake type: {$type->value}"),
            },
        );
    }
}
