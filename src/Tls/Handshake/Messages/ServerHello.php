<?php

declare(strict_types=1);

namespace Cloak\Tls\Handshake\Messages;

use InvalidArgumentException;
use Cloak\Tls\Extensions\BaseExtension;
use Cloak\Tls\Extensions\KeyShare;
use Cloak\Tls\Extensions\SupportedVersions;
use Cloak\Tls\Enums\CipherSuite;
use Cloak\Tls\Enums\ExtensionType;
use Cloak\Tls\Enums\ProtocolVersion;

class ServerHello extends BaseMessage
{
    public function __construct(
        public ProtocolVersion $legacy_version,
        public string $random, // random 32 bytes
        public string $legacy_session_id, // random 32 bytes
        public CipherSuite $cipher_suite,
        public int $legacy_compression_method,
        /** @var \Cloak\Tls\Extensions\BaseExtension[] $extensions */
        public array $extensions = [],
    ) {
        //
    }

    public function toBytes(): string
    {
        return '';
    }

    public static function fromBytes(string $data): self
    {
        return new self(
            legacy_version: ProtocolVersion::from(bytesToInt((takeBytes($data, 2)))),
            random: takeBytes($data, 32),
            legacy_session_id: takeBytes($data, bytesToInt(takeBytes($data, 1))),
            cipher_suite: CipherSuite::from(bytesToInt((takeBytes($data, 2)))),
            legacy_compression_method: bytesToInt(takeBytes($data, 1)),
            extensions: []
        )->extractExtensions($data);
    }

    public function extractExtensions(string $data): self
    {
        $extensionsLength = bytesToInt(takeBytes($data, 2));

        while (strlen($data) > 0) {
            $extensionType = ExtensionType::from(bytesToInt(takeBytes($data, 2)));
            $extensionLength = bytesToInt(takeBytes($data, 2));
            $extensionData = takeBytes($data, $extensionLength);

            $extension = match ($extensionType) {
                ExtensionType::KEY_SHARE => KeyShare::fromBytes($extensionData),
                ExtensionType::SUPPORTED_VERSIONS => SupportedVersions::fromBytes($extensionData),
                default => throw new InvalidArgumentException("Unsupported extension type: $extensionType->value"),
            };

            $this->extensions[] = $extension;
        }

        return $this;
    }

    public function findExtension(ExtensionType $type): ?BaseExtension
    {
        foreach ($this->extensions as $extension) {
            if ($extension->extension_type === $type) {
                return $extension;
            }
        }

        return null;
    }
}
