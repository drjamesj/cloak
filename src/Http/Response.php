<?php

declare(strict_types=1);

namespace Cloak\Http;

use InvalidArgumentException;

class Response
{
    private int $status;
    /** @var array<string, string> Associative array of headers where key is header name and value is header value */
    private array $headers = [];
    private string $body = '';

    public function setStatus(int $status): void
    {
        if ($status < 100 || $status > 599) {
            throw new InvalidArgumentException('Invalid HTTP status code: ' . $status);
        }

        $this->status = $status;
    }

    public function getStatus(): int
    {
        return $this->status;
    }

    public function setHeader(string $name, string $value): void
    {
        $this->headers[$name] = $value;
    }

    public function getHeader(string $name): ?string
    {
        return $this->headers[$name] ?? null;
    }

    /**
     * Get all headers as an associative array.
     * Keys are header names and values are header values.
     * 
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function setBody(string $body): void
    {
        $this->body = $body;
    }

    public function getBody(): string
    {
        return $this->body;
    }
}
