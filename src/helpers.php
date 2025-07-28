<?php

if (!function_exists('unit8')) {
    /**
     * Converts an integer to a 1-byte unsigned integer.
     *
     * @param int $value
     * @return string
     */
    function uint8(int $value): string
    {
        return pack('C', $value);
    }
}

if (!function_exists('uint16')) {
    /**
     * Converts an integer to a 2-byte unsigned integer.
     *
     * @param int $value
     * @return string
     */
    function uint16(int $value): string
    {
        return pack('n', $value);
    }
}

if (!function_exists('uint24')) {
    /**
     * Converts an integer to a 3-byte unsigned integer.
     *
     * @param int $value
     * @return string
     */
    function uint24(int $value): string
    {
        return substr(pack('N', $value), 1);
    }
}

if (!function_exists('uint32')) {
    /**
     * Converts an integer to a 4-byte unsigned integer.
     *
     * @param int $value
     * @return string
     */
    function uint32(int $value): string
    {
        return pack('N', $value);
    }
}

if (!function_exists('hexdump')) {
    /**
     * Converts a binary string to a human-readable hex string.
     *
     * @param string $data
     * @return string
     */
    function hexdump(string $data): string
    {
        return implode(' ', str_split(bin2hex($data), 2));
    }
}

if (!function_exists('takeBytes')) {
    /**
     * Takes a specified number of bytes from the beginning of a string.
     *
     * @param string $data
     * @param int $length
     * @return string
     */
    function takeBytes(string &$data, int $length): string
    {
        $bytes = substr($data, 0, $length);
        $data = substr($data, $length);

        return $bytes;
    }
}

if (!function_exists('bytesToInt')) {
    /**
     * Converts a byte string to an integer.
     *
     * @param string $data
     * @return int
     */
    function bytesToInt(string $data): int
    {
        $len = strlen($data);
        $value = 0;

        for ($i = 0; $i < $len; $i++) {
            $value = ($value << 8) | ord($data[$i]);
        }

        return $value;
    }
}
