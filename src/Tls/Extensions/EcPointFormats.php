<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;
use Cloak\Tls\Enums\GreaseValue;
use Cloak\Tls\Enums\NamedGroup;

class EcPointFormats extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::EC_POINT_FORMATS;

    /**
     * @param int[] $elliptic_curve_point_formats
     */
    public function __construct(
        public array $elliptic_curve_point_formats,
    ) {
    }

    /**
     * Create a new instance of EcPointFormats.
     *
     * @param int ...$elliptic_curve_point_formats
     */
    public static function make(...$elliptic_curve_point_formats): self
    {
        return new self(elliptic_curve_point_formats: $elliptic_curve_point_formats);
    }

    public function toBytes(): string
    {
        $elliptic_curve_point_formats = implode(array_map(fn (int $format) => uint8($format), $this->elliptic_curve_point_formats));
        $list = uint8(strlen($elliptic_curve_point_formats)) . $elliptic_curve_point_formats;

        return uint16($this->extension_type->value) . uint16(strlen($list)) . $list;
    }
}
