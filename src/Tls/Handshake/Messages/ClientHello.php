<?php

declare(strict_types=1);

namespace Cloak\Tls\Handshake\Messages;

use Cloak\Tls\Enums\CipherSuite;
use Cloak\Tls\Enums\GreaseValue;
use Cloak\Tls\Enums\HandshakeType;
use Cloak\Tls\Enums\ProtocolVersion;
use Cloak\Tls\Extensions\BaseExtension;

class ClientHello extends BaseMessage
{
    public function __construct(
        public ProtocolVersion $legacy_version,
        public string $random,
        public string $legacy_session_id,
        /** @var (\Cloak\Tls\Enums\CipherSuite|\Cloak\Tls\Enums\GreaseValue)[] */
        public array $cipher_suites = [],
        /** @var \Cloak\Tls\Extensions\BaseExtension[] */
        public array $extensions = [],
    ) {
        //
    }

    public static function make(): self
    {
        return new self(
            legacy_version: ProtocolVersion::TLS_1_2,
            random: random_bytes(32),
            legacy_session_id: random_bytes(32),
            cipher_suites: [],
            extensions: [],
        );
    }

    /**
     * @param \Cloak\Tls\Enums\CipherSuite|\Cloak\Tls\Enums\GreaseValue ...$cipher_suites
     */
    public function withCipherSuites(...$cipher_suites): self
    {
        $this->cipher_suites = $cipher_suites;

        return $this;
    }

    /**
     * @param \Cloak\Tls\Extensions\BaseExtension ...$extensions
     */
    public function withExtensions(...$extensions): self
    {
        $this->extensions = $extensions;

        return $this;
    }

    public function toBytes(): string
    {
        $handshakeType = HandshakeType::fromClass(static::class);

        $compressionMethods = uint8(0);

        $clientHello = implode([
            uint16($this->legacy_version->value),
            $this->random,
            uint8(strlen($this->legacy_session_id)) . $this->legacy_session_id,
            $this->cipherSuitesToBytes(),
            uint8(strlen($compressionMethods)) . $compressionMethods,
            $this->extensionsToBytes(),
        ]);

        return uint8($handshakeType->value) . uint24(strlen($clientHello)) . $clientHello;
    }

    private function cipherSuitesToBytes(): string
    {
        $cipherSuiteList = implode(array_map(fn(CipherSuite|GreaseValue $cipherSuite) => uint16($cipherSuite->value), $this->cipher_suites));

        return uint16(strlen($cipherSuiteList)) . $cipherSuiteList;
    }

    private function extensionsToBytes(): string
    {
        $extensionsList = implode(array_map(fn(BaseExtension $extension) => $extension->toBytes(), $this->extensions));

        return uint16(strlen($extensionsList)) . $extensionsList;
    }
}
