<?php

declare(strict_types=1);

namespace Cloak\Tcp;

use Closure;
use InvalidArgumentException;
use RuntimeException;

class TcpClient
{
    /** @var resource|false */
    private $stream;

    public function __construct(
        private string $host,
        private int $port,
    ) {
        //
    }

    public function getHost(): string
    {
        return $this->host;
    }

    public function getPort(): int
    {
        return $this->port;
    }

    public function connect(): self
    {
        $this->stream = stream_socket_client("tcp://{$this->host}:{$this->port}");

        return $this;
    }

    public function write(string $data): int|false
    {
        if ($this->stream === false) {
            throw new RuntimeException('Stream is not connected.');
        }

        return fwrite($this->stream, $data);
    }

    public function read(int $length): string
    {
        if ($this->stream === false) {
            throw new RuntimeException('Stream is not connected.');
        }

        if ($length <= 0) {
            throw new InvalidArgumentException('Length must be greater than 0');
        }

        $data = fread($this->stream, $length);
        if ($data === false) {
            throw new RuntimeException('Failed to read from stream.');
        }

        return $data;
    }
}
