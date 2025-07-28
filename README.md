# Cloak, low-level PHP HTTP and TLS 1.3 Client

![WIP](https://img.shields.io/badge/status-work_in_progress-yellow)

Cloak is a pure PHP HTTP and TLS client that allows for lower-level control over HTTP and TLS fingerprints.

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
