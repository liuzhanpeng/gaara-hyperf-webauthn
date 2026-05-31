<?php

declare(strict_types=1);

namespace GaaraHyperf\WebAuthn;

use GaaraHyperf\User\UserInterface;

/**
 * WebAuthn 用户接口.
 *
 * 应用的用户模型需实现此接口以支持 WebAuthn（Passkey）认证。
 *
 * `getIdentifier()` 返回的值将用作 WebAuthn 用户句柄（user handle）。
 * 用户句柄不应超过 64 字节，推荐使用 UUID 或数字 ID。
 *
 * 用法示例：
 * ```php
 * class User implements WebAuthnUserInterface {
 *     public function getIdentifier(): string { return (string) $this->id; }
 *     public function getWebAuthnDisplayName(): string { return $this->name; }
 * }
 * ```
 */
interface WebAuthnUserInterface extends UserInterface
{
    /**
     * 返回显示给用户的名称（如姓名或用户名）。
     *
     * 不影响安全性，仅用于认证器的界面展示。
     */
    public function getWebAuthnDisplayName(): string;
}
