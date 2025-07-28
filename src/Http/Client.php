<?php

declare(strict_types=1);

namespace Cloak\Http;

use Cloak\Tcp\TcpClient;
use Cloak\Tls\TlsClient;
use RuntimeException;

class Client
{
    public function __construct(
        private HttpVersion $httpVersion = HttpVersion::HTTP_1_1
    ) {
        //
    }

    public function get(string $url): Response
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);
        $host = parse_url($url, PHP_URL_HOST);
        $port = parse_url($url, PHP_URL_PORT) ?: ($scheme === 'https' ? 443 : 80);

        if (!$host) {
            throw new RuntimeException("Invalid host in URL: $url");
        }

        $tcpClient = new TcpClient($host, $port)->connect();
        $tlsClient = new TlsClient($tcpClient, $scheme === 'https');

        if ($this->httpVersion === HttpVersion::HTTP_1_1) {
            $httpClient = new ClientV1(tlsClient: $tlsClient);
        } else {
            throw new RuntimeException('Unsupported HTTP version: ' . $this->httpVersion->value);
        }

        return $httpClient->get($url);
    }
}
