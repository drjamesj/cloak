<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Contracts\HasBytes;
use Cloak\Tls\Enums\ExtensionType;

abstract class BaseExtension implements HasBytes
{
    public ExtensionType $extension_type;
}
