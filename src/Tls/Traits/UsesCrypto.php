<?php

declare(strict_types=1);

namespace Cloak\Tls\Traits;

trait UsesCrypto
{
    public function hkdf_extract(string $salt, string $ikm): string
    {
        return hash_hmac('sha256', $ikm, $salt, true);
    }

    public function hkdf_expand_label(string $secret, string $label, string $context, int $length): string
    {
        $full_label = "tls13 " . $label;

        $hkdf_label = pack('n', $length)
            . pack('C', strlen($full_label)) . $full_label
            . pack('C', strlen($context)) . $context;

        return $this->hkdf_expand($secret, $hkdf_label, $length);
    }

    public function hkdf_expand(string $prk, string $info, int $length): string
    {
        $hash_len = 32; // SHA-256
        $n = ceil($length / $hash_len);
        $t = '';
        $okm = '';

        for ($i = 1; $i <= $n; $i++) {
            $t = hash_hmac('sha256', $t . $info . chr($i), $prk, true);
            $okm .= $t;
        }

        return substr($okm, 0, $length);
    }

    public function make_nonce(string $iv, int $seq): string
    {
        $seq_bytes = pack('NN', $seq >> 32, $seq & 0xFFFFFFFF);
        $seq_bytes = str_pad($seq_bytes, 12, "\x00", STR_PAD_LEFT);
        return $this->xor_bytes($iv, $seq_bytes);
    }

    public function xor_bytes(string $a, string $b): string
    {
        $out = '';
        for ($i = 0; $i < strlen($a); $i++) {
            $out .= $a[$i] ^ $b[$i];
        }
        return $out;
    }
}
