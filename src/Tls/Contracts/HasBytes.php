<?php

declare(strict_types=1);

namespace Cloak\Tls\Contracts;

interface HasBytes
{
    /**
     * Returns the byte stream representation of the object.
     *
     * @return string
     */
    public function toBytes(): string;
}
