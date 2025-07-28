<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

class Grease
{
    public static array $cipher_suites = [
        0x0a0a,
        0x1a1a,
        0x2a2a,
        0x3a3a,
        0x4a4a,
        0x5a5a,
        0x6a6a,
        0x7a7a,
        0x8a8a,
        0x9a9a,
        0xaaaa,
        0xbaba,
        0xcaca,
        0xdada,
        0xeaea,
        0xfafa,
    ];

    public static function cipherSuite(): string
    {
        return self::$cipher_suites[array_rand(self::$cipher_suites)];
    }

    public static function extension(): string
    {
        // todo
    }

    /**
     * Randomises the given extensions by adding a GREASE value to each.
     *
     * @param \Cloak\Tls\Extensions\BaseExtension ...$extensions
     * 
     * @return \Cloak\Tls\Extensions\BaseExtension[]
     */
    public static function randomiseExtensions(...$extensions): array
    {
        shuffle($extensions);

        return [
            self::extension(),
            ...$extensions,
        ];
    }
}
