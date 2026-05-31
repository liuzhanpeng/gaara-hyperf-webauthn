<?php

declare(strict_types=1);

namespace GaaraHyperf\WebAuthn\ChallengeStorage;

use Hyperf\Contract\SessionInterface;

/**
 * 基于 Session 的 WebAuthn 挑战存储.
 *
 * 适合传统 Web 场景（Session 有状态认证流程）。
 */
class SessionChallengeStorage implements ChallengeStorageInterface
{
    private const SESSION_PREFIX = '_gaara_webauthn_challenge_';

    public function __construct(
        private SessionInterface $session,
    ) {
    }

    public function store(string $challengeId, WebAuthnChallenge $challenge): void
    {
        $this->session->set(
            self::SESSION_PREFIX . $challengeId,
            json_encode([
                'type' => $challenge->type,
                'user_identifier' => $challenge->userIdentifier,
                'challenge_bytes' => base64_encode($challenge->challengeBytes),
                'issued_at' => $challenge->issuedAt,
                'metadata' => $challenge->metadata,
            ])
        );
    }

    public function get(string $challengeId): ?WebAuthnChallenge
    {
        $raw = $this->session->get(self::SESSION_PREFIX . $challengeId);
        if (! is_string($raw)) {
            return null;
        }

        $data = json_decode($raw, true);
        if (! is_array($data)
            || ! isset($data['type'], $data['challenge_bytes'], $data['issued_at'])
        ) {
            return null;
        }

        return new WebAuthnChallenge(
            $data['type'],
            $data['user_identifier'] ?? null,
            base64_decode($data['challenge_bytes']),
            (int) $data['issued_at'],
            $data['metadata'] ?? [],
        );
    }

    public function delete(string $challengeId): void
    {
        $this->session->remove(self::SESSION_PREFIX . $challengeId);
    }
}
