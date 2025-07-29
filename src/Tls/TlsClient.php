<?php

declare(strict_types=1);

namespace Cloak\Tls;

use Cloak\Tcp\TcpClient;
use Cloak\Tls\Enums\ApplicationLayerProtocol;
use Cloak\Tls\Enums\CipherSuite;
use Cloak\Tls\Enums\ContentType;
use Cloak\Tls\Enums\ExtensionType;
use Cloak\Tls\Enums\HandshakeType;
use Cloak\Tls\Enums\NamedGroup;
use Cloak\Tls\Enums\ProtocolVersion;
use Cloak\Tls\Enums\SignatureAlgorithm;
use Cloak\Tls\Extensions\ApplicationLayerProtocolNegotiation;
use Cloak\Tls\Extensions\CompressCertificate;
use Cloak\Tls\Extensions\EcPointFormats;
use Cloak\Tls\Extensions\EncryptedClientHello;
use Cloak\Tls\Extensions\ExtendedMasterSecret;
use Cloak\Tls\Extensions\ExtensionRenegotiationInfo;
use Cloak\Tls\Extensions\Grease;
use Cloak\Tls\Extensions\KeyShare;
use Cloak\Tls\Extensions\KeyShareEntry;
use Cloak\Tls\Extensions\PskKeyExchangeModes;
use Cloak\Tls\Extensions\ServerName;
use Cloak\Tls\Extensions\SessionTicket;
use Cloak\Tls\Extensions\SignatureAlgorithms;
use Cloak\Tls\Extensions\SignedCertificateTimestamp;
use Cloak\Tls\Extensions\StatusRequest;
use Cloak\Tls\Extensions\SupportedGroups;
use Cloak\Tls\Extensions\SupportedVersions;
use Cloak\Tls\Records\Handshake;
use Cloak\Tls\Handshake\Messages\ClientHello;
use Cloak\Tls\Handshake\Messages\Finished;
use Cloak\Tls\Handshake\Messages\ServerHello;
use Cloak\Tls\Records\ApplicationData;
use Cloak\Tls\Records\Record;
use Exception;
use InvalidArgumentException;
use RuntimeException;

class TlsClient
{
    use Traits\UsesCrypto;

    /** @var TcpClient */
    private $tcpClient;
    private bool $isEnabled = true;
    private bool $handshakeComplete = false;
    private bool $logKeys = false;

    private string $transcript = '';
    private string $keypair = '';

    private ?string $server_hs_traffic_secret = null;
    private ?string $client_hs_traffic_secret = null;

    private ?string $server_app_traffic_secret = null;
    private ?string $client_app_traffic_secret = null;

    private int $client_record_seq_num  = 0;
    private int $server_record_seq_num = 0;

    private string $handshake_secret = '';

    private ?ClientHello $clientHello = null;

    public function __construct(
        TcpClient $tcpClient,
        bool $isEnabled = true,
        bool $logKeys = true,
    ) {
        $this->isEnabled = $isEnabled;
        $this->logKeys = $logKeys;
        $this->setTcpClient($tcpClient);

        if ($this->isEnabled) {
            $this->executeHandshake();
        }
    }

    public function setTcpClient(TcpClient $tcpClient): void
    {
        $this->tcpClient = $tcpClient;
    }

    public function write(string $data): void
    {
        if (!$this->isEnabled || !$this->handshakeComplete) {
            $this->tcpClient->write($data);
        } else {
            $key = $this->hkdf_expand_label(
                $this->client_app_traffic_secret,
                "key",
                "",
                16
            );
            $iv  = $this->hkdf_expand_label(
                $this->client_app_traffic_secret,
                "iv",
                "",
                12
            );

            $nonce = $this->make_nonce($iv, $this->client_record_seq_num);

            $aad = pack('C', ContentType::APPLICATION_DATA->value)
                . pack('n', 0x0303)
                . pack('n', strlen($data) + 1 + 16); // +16 byte GCM tag

            $cipher = openssl_encrypt(
                $data . chr(0x17), // 0x17 is the content type for Application Data
                'aes-128-gcm',
                $key,
                OPENSSL_RAW_DATA,
                $nonce,
                $tag,
                $aad
            );

            $payload = $cipher . $tag;
            $record  = pack('C', ContentType::APPLICATION_DATA->value)
                . pack('n', 0x0303)
                . pack('n', strlen($payload))
                . $payload;

            $this->tcpClient->write($record);
            $this->client_record_seq_num++;
        }
    }

    public function read(int $bytes = 16384): string
    {
        if (!$this->isEnabled || !$this->handshakeComplete) {
            return $this->tcpClient->read($bytes);
        } else {
            $record = $this->readRecord();

            if ($record->fragment instanceof ApplicationData) {
                return $record->fragment->record->data;
            }

            return '';
        }
    }

    public function readRecord(): Record
    {
        $recordHeader = $this->tcpClient->read(5);
        [$type, $version, $length] = array_values(unpack('Ctype/nversion/nlength', $recordHeader) ?: throw new RuntimeException('Failed to unpack record header'));
        $contentType = ContentType::from($type);

        $rawFragment = '';
        while (strlen($rawFragment) < $length) {
            $chunk = $this->tcpClient->read($length - strlen($rawFragment));

            if ($chunk === '') {
                echo "Failed to read fragment data\n";
                break;
            }

            $rawFragment .= $chunk;
        }

        if ($contentType === ContentType::APPLICATION_DATA) {
            if ($this->handshakeComplete) {
                $server_key = $this->hkdf_expand_label($this->server_app_traffic_secret, "key", "", 16);
                $server_iv  = $this->hkdf_expand_label($this->server_app_traffic_secret, "iv", "", 12);
            } else {
                $server_key = $this->hkdf_expand_label($this->server_hs_traffic_secret, "key", "", 16);
                $server_iv  = $this->hkdf_expand_label($this->server_hs_traffic_secret, "iv", "", 12);
            }

            $nonce = $this->make_nonce($server_iv, $this->server_record_seq_num);
            $tag = substr($rawFragment, -16);
            $ciphertext = substr($rawFragment, 0, -16);

            $aead_aad = pack('C', ContentType::APPLICATION_DATA->value)
                . pack('n', 0x0303)
                . pack('n', strlen($ciphertext) + strlen($tag));

            $decrypted = openssl_decrypt(
                $ciphertext,
                'aes-128-gcm',
                $server_key,
                OPENSSL_RAW_DATA,
                $nonce,
                $tag,
                $aead_aad,
            );

            $this->server_record_seq_num++;

            return Record::fromBytes(
                type: $type,
                legacy_record_version: $version,
                fragment: $decrypted ?: null,
                rawFragment: $decrypted ?: null,
            );
        }

        return Record::fromBytes(
            type: $type,
            legacy_record_version: $version,
            fragment: $rawFragment,
            rawFragment: $rawFragment,
        );
    }

    public function processRecord(Record $record): void
    {
        if ($record->type === ContentType::HANDSHAKE) {
            if ($record->fragment instanceof Handshake) {
                $msg = $record->fragment->msg;
                if ($msg instanceof ServerHello) {
                    /** @var \Cloak\Tls\Extensions\KeyShare $keyShareExtension */
                    $keyShareExtension = $msg->findExtension(ExtensionType::KEY_SHARE);
                    $serverPublicKey = $keyShareExtension->entries[0]->key_exchange;

                    $sharedSecret = sodium_crypto_scalarmult(
                        $this->getClientPrivateKey(),
                        $serverPublicKey
                    );

                    $zero = str_repeat("\x00", 32);
                    $earlySecret = $this->hkdf_extract($zero, $zero);
                    $emptyHash = hash('sha256', '', true);
                    $derivedEarly = $this->hkdf_expand_label($earlySecret, "derived", $emptyHash, 32);

                    $this->handshake_secret = $this->hkdf_extract($derivedEarly, $sharedSecret);

                    $this->transcript .= $record->rawFragment;
                    $transcript_hash = hash('sha256', $this->transcript, true);

                    $this->client_hs_traffic_secret = $this->hkdf_expand_label($this->handshake_secret, "c hs traffic", $transcript_hash, 32);
                    $this->server_hs_traffic_secret = $this->hkdf_expand_label($this->handshake_secret, "s hs traffic", $transcript_hash, 32);
                }
            }
        } else if (
            $record->fragment instanceof ApplicationData &&
            $record->fragment->record instanceof Handshake &&
            $record->fragment->record->msg instanceof Finished
        ) {
            $offset = 0;
            $content = $record->rawFragment;

            $msgLength = unpack('N', "\x00" . substr($content, $offset + 1, 3))[1] ?? throw new InvalidArgumentException('Invalid message length in content: ' . bin2hex($content));
            $messageData = substr($content, $offset + 4, $msgLength);

            $this->processServerFinished(
                $messageData,
                substr($content, $offset, 4 + $msgLength),
            );
        } else if (
            $record->fragment instanceof ApplicationData &&
            $record->fragment->record instanceof Handshake
        ) {
            if (in_array($record->fragment->record->msg_type, [
                HandshakeType::ENCRYPTED_EXTENSIONS,
                HandshakeType::CERTIFICATE,
                HandshakeType::CERTIFICATE_VERIFY,
            ])) {
                $this->transcript .= $record->fragment->raw;
            }
        }
    }

    private function processServerFinished(string $messageData, string $fullMessage): void
    {
        // 1. Verify the server's Finished message
        $server_finished_key = $this->hkdf_expand_label($this->server_hs_traffic_secret, "finished", "", 32);
        $transcript_hash = hash('sha256', $this->transcript, true);
        $expected = hash_hmac('sha256', $transcript_hash, $server_finished_key, true);
        if (!hash_equals($expected, $messageData)) {
            throw new RuntimeException("Server Finished verify_data mismatch");
        }

        // 2. Append the server Finished message to the transcript
        $this->transcript .= $fullMessage;
        $transcript_hash = hash('sha256', $this->transcript, true);

        // 3. Next we derive client and server application traffic secrets
        $emptyHash = hash('sha256', '', true);
        $derived_handshake_secret = $this->hkdf_expand_label($this->handshake_secret, "derived", $emptyHash, 32);
        $master_secret = $this->hkdf_extract($derived_handshake_secret, str_repeat("\x00", 32));
        $this->client_app_traffic_secret = $this->hkdf_expand_label($master_secret, "c ap traffic", $transcript_hash, 32);
        $this->server_app_traffic_secret = $this->hkdf_expand_label($master_secret, "s ap traffic", $transcript_hash, 32);


        if ($this->logKeys) {
            $client_random_hex = bin2hex($this->clientHello->random);
            file_put_contents(
                "./tls13_keylog.log",
                sprintf("CLIENT_HANDSHAKE_TRAFFIC_SECRET %s %s\n", $client_random_hex, bin2hex($this->client_hs_traffic_secret)),
                FILE_APPEND
            );
            file_put_contents(
                "./tls13_keylog.log",
                sprintf("SERVER_HANDSHAKE_TRAFFIC_SECRET %s %s\n", $client_random_hex, bin2hex($this->server_hs_traffic_secret)),
                FILE_APPEND
            );
            file_put_contents(
                "./tls13_keylog.log",
                sprintf("CLIENT_TRAFFIC_SECRET_0 %s %s\n", $client_random_hex, bin2hex($this->client_app_traffic_secret)),
                FILE_APPEND
            );
            file_put_contents(
                "./tls13_keylog.log",
                sprintf("SERVER_TRAFFIC_SECRET_0 %s %s\n", $client_random_hex, bin2hex($this->server_app_traffic_secret)),
                FILE_APPEND
            );
        }

        // 4. Build and send Client Finished message
        $client_finished_key = $this->hkdf_expand_label($this->client_hs_traffic_secret, "finished", "", 32);
        $verify_data = hash_hmac('sha256', $transcript_hash, $client_finished_key, true);
        $handshake_type = chr(0x14); // Finished
        $length = pack('N', strlen($verify_data)); // 3-byte length
        $length = substr($length, 1); // take last 3 bytes
        $handshake_msg = $handshake_type . $length . $verify_data;
        $plaintext_with_type = $handshake_msg . chr(0x16); // 0x16 is the content type for Handshake
        $client_key = $this->hkdf_expand_label($this->client_hs_traffic_secret, "key", "", 16);
        $client_iv  = $this->hkdf_expand_label($this->client_hs_traffic_secret, "iv", "", 12);
        $nonce = $this->make_nonce($client_iv, $this->client_record_seq_num);
        $aad = pack('C', ContentType::APPLICATION_DATA->value)
            . pack('n', 0x0303)
            . pack('n', strlen($plaintext_with_type) + 16); // +16 for the GCM tag
        $encrypted = openssl_encrypt(
            $plaintext_with_type,
            'aes-128-gcm',
            $client_key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad
        );
        $encrypted_payload = $encrypted . $tag;
        $record = pack('C', ContentType::APPLICATION_DATA->value)
            . pack('n', 0x0303)
            . pack('n', strlen($encrypted_payload))
            . $encrypted_payload;
        $this->write($record);
        $this->client_record_seq_num++;

        // 5. Append client Finished message to the transcript
        $this->transcript .= $plaintext_with_type;
        $transcript_hash = hash('sha256', $this->transcript, true);

        // 6. Switch flags
        $this->handshakeComplete = true;
        $this->client_record_seq_num = 0;
        $this->server_record_seq_num = 0;
    }

    private function executeHandshake(): void
    {
        $this->keypair = sodium_crypto_box_keypair();

        $this->sendClientHello();

        while (!$this->handshakeComplete) {
            $record = $this->readRecord();
            $this->processRecord($record);
        }
    }

    public function getClientPrivateKey(): string
    {
        return sodium_crypto_box_secretkey($this->keypair);
    }

    public function getClientPublicKey(): string
    {
        return sodium_crypto_box_publickey($this->keypair);
    }

    private function sendClientHello(): void
    {
        $this->clientHello = ClientHello::make()
            ->withCipherSuites(
                Grease::cipherSuite(),
                CipherSuite::TLS_AES_128_GCM_SHA256,
                CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
            )->withExtensions(
                ...Grease::randomiseExtensions(
                    ServerName::make($this->tcpClient->getHost()),
                    SupportedVersions::make(
                        Grease::randomGreaseValue(),
                        ProtocolVersion::TLS_1_3,
                        ProtocolVersion::TLS_1_2,
                    ),
                    KeyShare::make(
                        KeyShareEntry::make(
                            NamedGroup::X25519MLKEM768,
                            random_bytes(32 + 1184),
                        ),
                        KeyShareEntry::make(
                            NamedGroup::X25519,
                            $this->getClientPublicKey(),
                        ),
                        KeyShareEntry::make(
                            Grease::randomGreaseValue(),
                            uint8(0x00),
                        )
                    ),
                    SignatureAlgorithms::make(
                        SignatureAlgorithm::ECDSA_SECP256R1_SHA256,
                        SignatureAlgorithm::RSA_PSS_RSAE_SHA256,
                        SignatureAlgorithm::RSA_PKCS1_SHA256,
                        SignatureAlgorithm::ECDSA_SECP384R1_SHA384,
                        SignatureAlgorithm::RSA_PSS_RSAE_SHA384,
                        SignatureAlgorithm::RSA_PKCS1_SHA384,
                        SignatureAlgorithm::RSA_PSS_RSAE_SHA512,
                        SignatureAlgorithm::RSA_PKCS1_SHA512,
                    ),
                    SupportedGroups::make(
                        Grease::randomGreaseValue(),
                        NamedGroup::X25519MLKEM768,
                        NamedGroup::X25519,
                        NamedGroup::SECP256R1,
                        NamedGroup::SECP384R1,
                    ),
                    ApplicationLayerProtocolNegotiation::make([
                        // ApplicationLayerProtocol::HTTP_2,
                        ApplicationLayerProtocol::HTTP_1_1,
                    ]),
                    SignedCertificateTimestamp::make(),
                    EcPointFormats::make(0x00),
                    ExtendedMasterSecret::make('', ''),
                    PskKeyExchangeModes::make(0x01), // Enabling PSK results in a new session ticket message being received
                    SessionTicket::make(''),
                    ExtensionRenegotiationInfo::make(uint8(0x00)),
                    CompressCertificate::make(
                        0x02, // 0x02 is the compression method for "brotli"
                    ),
                    EncryptedClientHello::makeGrease(),
                    StatusRequest::make(),
                ),
            );

        $this->transcript .= $this->clientHello->toBytes();

        $this->write($this->clientHello->toHandshake()->toRecord()->toBytes());
    }
}
