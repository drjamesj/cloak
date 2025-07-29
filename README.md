# Cloak, a low-level HTTP and TLS 1.3 Client in PHP

![WIP](https://img.shields.io/badge/status-work_in_progress-yellow)

Cloak is a pure PHP HTTP and TLS client that allows for low-level control over HTTP and TLS fingerprints.

## Installing Cloak

```bash
composer require exe/cloak
```

## Usage

```php
use Cloak\Http\Client;

$client = new Client(); // Initialises a HTTP/1.1 client by default

$response = $client->get('https://tls.peet.ws/api/all');

echo $response->getStatus(); // 200
echo $response->getHeader('content-type'); // application/json; charset=utf-8
echo $response->getBody(); // '{...}'
```

## Roadmap

- [ ] HTTP/1.1 implementation
- [ ] HTTP/2 implementation
- [ ] Browser profiles

## Resources

- [IETF RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [IETF RFC 8701 - Applying Generate Random Extensions And Sustain Extensibility (GREASE) to TLS Extensibility](https://datatracker.ietf.org/doc/html/rfc8701)
- [Hybrid key exchange in TLS 1.3](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
- [IETF RFC 6962 - Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
- [IETF RFC 8879 - TLS Certificate Compression](https://datatracker.ietf.org/doc/html/rfc8879)
