<?php

declare(strict_types=1);

namespace Cloak\Tls\Extensions;

use Cloak\Tls\Enums\ExtensionType;
use Cloak\Tls\Enums\GreaseValue;
use Cloak\Tls\Enums\NamedGroup;

class SupportedGroups extends BaseExtension
{
    public ExtensionType $extension_type = ExtensionType::SUPPORTED_GROUPS;

    /**
     * @param (\Cloak\Tls\Enums\NamedGroup|\Cloak\Tls\Enums\GreaseValue)[] $named_group_list
     */
    public function __construct(
        public array $named_group_list,
    ) {
    }

    /**
     * Create a new instance of SupportedGroups.
     *
     * @param \Cloak\Tls\Enums\NamedGroup|\Cloak\Tls\Enums\GreaseValue ...$named_group_list
     */
    public static function make(...$named_group_list): self
    {
        return new self(named_group_list: $named_group_list);
    }

    public function toBytes(): string
    {
        $named_group_list = implode(array_map(fn (NamedGroup|GreaseValue $named_group) => uint16($named_group->value), $this->named_group_list));
        $list = uint16(strlen($named_group_list)) . $named_group_list;

        return uint16($this->extension_type->value) . uint16(strlen($list)) . $list;
    }
}
