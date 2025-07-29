<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\GreaseValue;
use RuntimeException;

class Grease
{
    /** @var int[] */
    private static array $used = [];

    public static function randomGreaseValue(): GreaseValue
    {
        $values = array_map(fn (GreaseValue $value) => $value->value, GreaseValue::cases());

        $available = array_diff($values, self::$used);

        if (empty($available)) {
            throw new RuntimeException('No available GREASE values');
        }

        $selected = $available[array_rand($available)];

        self::$used[] = $selected;

        return GreaseValue::from($selected);
    }

    public static function cipherSuite(): GreaseValue
    {
        $selected = self::randomGreaseValue();

        self::$used[] = $selected->value;

        return $selected;
    }

    public static function extension(): BaseExtension
    {
        return new class (self::randomGreaseValue()) extends BaseExtension {
            public function __construct(
                public readonly GreaseValue $grease_value,
            ) {
                //
            }

            public function toBytes(): string
            {
                $payload = uint16(0x00);

                return uint16($this->grease_value->value) . uint16(strlen($payload)) . $payload;
            }
        };
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
            self::extension(),
        ];
    }
}
