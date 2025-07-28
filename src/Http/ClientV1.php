<?php

declare(strict_types=1);

namespace Cloak\Http;

use Cloak\Tls\TlsClient;
use InvalidArgumentException;

class ClientV1
{
    public function __construct(
        private TlsClient $tlsClient,
    ) {
        //
    }

    public function get(string $url): Response
    {
        $host = parse_url($url, PHP_URL_HOST);
        $path = parse_url($url, PHP_URL_PATH) ?: '/';

        $request = "GET $path HTTP/1.1\r\n" .
            "Host: $host\r\n" .
            "Connection: close\r\n\r\n";

        $this->tlsClient->write($request);

        $contentLength = null;
        $headerEnd = null;
        $buffer = '';

        while (true) {
            $buffer .= $this->tlsClient->read();

            if ($headerEnd === null && str_contains($buffer, "\r\n\r\n")) {
                $headerEnd = strpos($buffer, "\r\n\r\n") + 4;

                $headers = explode("\r\n", $buffer);
                foreach ($headers as $header) {
                    if (preg_match('/^Content-Length:\s*(\d+)/i', $header, $matches)) {
                        $contentLength = (int)$matches[1];
                    }
                }
            }

            if ($contentLength !== null && strlen($buffer) >= $headerEnd + $contentLength) {
                break;
            }
        }

        return $this->parseResponse(trim($buffer));
    }

    private function parseResponse(string $raw): Response
    {
        $response = new Response();

        $parts = explode("\r\n\r\n", $raw, 2);
        if (count($parts) < 2) {
            throw new InvalidArgumentException('Invalid HTTP response format');
        }

        $headerLines = explode("\r\n", $parts[0]);
        $statusLine = $headerLines[0];
        if (preg_match('/HTTP\/\d\.\d (\d{3})/', $statusLine, $matches)) {
            $response->setStatus((int)$matches[1]);
        } else {
            throw new InvalidArgumentException('Invalid HTTP status line: ' . $statusLine);
        }

        foreach ($headerLines as $line) {
            if (preg_match('/^([^:]+): (.+)$/', $line, $matches)) {
                $response->setHeader(strtolower(trim($matches[1])), trim($matches[2]));
            }
        }

        $response->setBody($parts[1]);

        return $response;
    }
}
