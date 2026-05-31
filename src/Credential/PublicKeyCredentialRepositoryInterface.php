<?php

declare(strict_types=1);

namespace GaaraHyperf\WebAuthn\Credential;

use Webauthn\PublicKeyCredentialSource;

/**
 * WebAuthn 凭据仓库接口.
 *
 * 应用需在容器中绑定此接口的实现（通常持久化到数据库）。
 *
 * 示例绑定（ConfigProvider 或启动代码中）：
 * ```php
 * $container->bind(
 *     PublicKeyCredentialRepositoryInterface::class,
 *     MyCredentialRepository::class
 * );
 * ```
 */
interface PublicKeyCredentialRepositoryInterface
{
    /**
     * 根据凭据 ID（二进制）查找凭据源.
     *
     * @param string $credentialId 二进制格式的凭据 ID（即 PublicKeyCredentialSource::$publicKeyCredentialId）
     */
    public function findByCredentialId(string $credentialId): ?PublicKeyCredentialSource;

    /**
     * 返回指定用户的全部凭据.
     *
     * @param string $userIdentifier 用户标识符（与 UserInterface::getIdentifier() 相同）
     * @return PublicKeyCredentialSource[]
     */
    public function findAllByUserIdentifier(string $userIdentifier): array;

    /**
     * 持久化凭据（新增或更新 signCount）.
     */
    public function save(PublicKeyCredentialSource $source): void;
}
