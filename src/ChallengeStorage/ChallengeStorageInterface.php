<?php

declare(strict_types=1);

namespace GaaraHyperf\WebAuthn\ChallengeStorage;

/**
 * WebAuthn 挑战存储接口.
 *
 * 负责持久化待验证挑战，并在注册/登录验证阶段检索、删除挑战。
 */
interface ChallengeStorageInterface
{
    /**
     * 存储挑战.
     *
     * @param string $challengeId 唯一挑战 ID
     * @param WebAuthnChallenge $challenge 挑战数据
     */
    public function store(string $challengeId, WebAuthnChallenge $challenge): void;

    /**
     * 获取挑战.
     *
     * 若不存在则返回 null。
     */
    public function get(string $challengeId): ?WebAuthnChallenge;

    /**
     * 删除挑战（验证通过或过期后调用）.
     */
    public function delete(string $challengeId): void;
}
