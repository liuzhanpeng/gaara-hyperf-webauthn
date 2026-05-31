<?php

declare(strict_types=1);

namespace GaaraHyperf\WebAuthn\ChallengeStorage;

/**
 * WebAuthn 挑战数据.
 *
 * 存储挑战的关联元数据，用于在验证阶段还原操作上下文。
 *
 * @property array<string, mixed> $metadata 额外元数据
 *                                          - registration: ['creation_options' => JSON string]
 *                                          - authentication: ['request_options' => JSON string]
 */
class WebAuthnChallenge
{
    public function __construct(
        /** 'registration' 或 'authentication' */
        public readonly string $type,
        /** 发起挑战的用户标识符（discoverable 流程为 null） */
        public readonly ?string $userIdentifier,
        /** 挑战字节（binary string） */
        public readonly string $challengeBytes,
        /** Unix 时间戳 */
        public readonly int $issuedAt,
        /** 存储序列化后的 PublicKeyCredential*Options JSON */
        public readonly array $metadata = [],
    ) {
    }

    public function isExpired(int $ttl): bool
    {
        return (time() - $this->issuedAt) > $ttl;
    }
}
