<?php

declare(strict_types=1);

namespace GaaraHyperf\WebAuthn\Service;

use GaaraHyperf\WebAuthn\ChallengeStorage\ChallengeStorageInterface;
use GaaraHyperf\WebAuthn\ChallengeStorage\WebAuthnChallenge;
use GaaraHyperf\WebAuthn\Credential\PublicKeyCredentialRepositoryInterface;
use GaaraHyperf\WebAuthn\WebAuthnAuthenticator;
use GaaraHyperf\WebAuthn\WebAuthnUserInterface;
use RuntimeException;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * WebAuthn 高层管理服务.
 *
 * 应用在自己的 Controller 中注入此服务，用于：
 * - 发起注册（生成 PublicKeyCredentialCreationOptions）
 * - 完成注册（验证认证器响应，持久化凭据）
 * - 发起登录（生成 PublicKeyCredentialRequestOptions）
 *
 * 登录断言验证由 {@see WebAuthnAuthenticator} 处理，不在此服务中。
 *
 * 用法示例（Hyperf Controller）：
 * ```php
 * #[PostMapping('/webauthn/register/options')]
 * public function registrationOptions(WebAuthnManager $manager): ResponseInterface
 * {
 *     $user = auth()->user();
 *     ['challenge_id' => $id, 'options' => $options] = $manager->startRegistration($user, $this->request);
 *     return $this->response->json(['challenge_id' => $id, 'options' => $options]);
 * }
 * ```
 */
class WebAuthnManager
{
    public function __construct(
        private string $rpName,
        private string $rpId,
        private int $challengeTtl,
        private ?int $timeout,
        private string $userVerification,
        private ChallengeStorageInterface $challengeStorage,
        private PublicKeyCredentialRepositoryInterface $credentialRepository,
        private WebAuthnFactory $factory,
    ) {
    }

    /**
     * 生成注册选项并存储挑战.
     *
     * @return array{'challenge_id': string, 'options': array<string, mixed>}
     */
    public function startRegistration(WebAuthnUserInterface $user): array
    {
        $challengeBytes = random_bytes(32);
        $challengeId = bin2hex(random_bytes(16));

        $options = PublicKeyCredentialCreationOptions::create(
            rp: PublicKeyCredentialRpEntity::create($this->rpName, $this->rpId),
            user: PublicKeyCredentialUserEntity::create(
                name: $user->getIdentifier(),
                id: $user->getIdentifier(),
                displayName: $user->getWebAuthnDisplayName(),
            ),
            challenge: $challengeBytes,
            pubKeyCredParams: [
                PublicKeyCredentialParameters::create('public-key', -7),   // ES256
                PublicKeyCredentialParameters::create('public-key', -257), // RS256
            ],
            timeout: $this->timeout,
        );

        $serializer = $this->factory->getSerializer();
        $optionsJson = $serializer->serialize($options, 'json');

        $this->challengeStorage->store($challengeId, new WebAuthnChallenge(
            type: 'registration',
            userIdentifier: $user->getIdentifier(),
            challengeBytes: $challengeBytes,
            issuedAt: time(),
            metadata: ['creation_options' => $optionsJson],
        ));

        return [
            'challenge_id' => $challengeId,
            'options' => json_decode($optionsJson, true, 512, JSON_THROW_ON_ERROR),
        ];
    }

    /**
     * 验证注册响应并持久化凭据.
     *
     * @param array<string, mixed> $credentialData 来自前端的 navigator.credentials.create() 响应（JSON 解码后的数组）
     *
     * @throws AuthenticatorResponseVerificationException 验证失败时抛出
     * @throws RuntimeException 挑战无效或已过期时抛出
     */
    public function finishRegistration(string $challengeId, array $credentialData, string $host): PublicKeyCredentialSource
    {
        $challenge = $this->challengeStorage->get($challengeId);
        if ($challenge === null) {
            throw new RuntimeException('Invalid or expired WebAuthn challenge.');
        }
        if ($challenge->isExpired($this->challengeTtl)) {
            $this->challengeStorage->delete($challengeId);
            throw new RuntimeException('WebAuthn challenge has expired.');
        }
        if ($challenge->type !== 'registration') {
            throw new RuntimeException('Challenge type mismatch: expected registration.');
        }

        $serializer = $this->factory->getSerializer();

        $options = $serializer->deserialize(
            $challenge->metadata['creation_options'],
            PublicKeyCredentialCreationOptions::class,
            'json'
        );

        $credential = $serializer->deserialize(
            json_encode($credentialData, JSON_THROW_ON_ERROR),
            PublicKeyCredential::class,
            'json'
        );

        $credential->response instanceof AuthenticatorAttestationResponse
            || throw new RuntimeException('Invalid credential response type: expected attestation.');

        $source = $this->factory->createAttestationValidator()->check(
            $credential->response,
            $options,
            $host,
        );

        $this->credentialRepository->save($source);
        $this->challengeStorage->delete($challengeId);

        return $source;
    }

    /**
     * 生成登录选项并存储挑战.
     *
     * 若提供 $userIdentifier，则仅允许该用户已注册的凭据（非 discoverable 流程）。
     * 若 $userIdentifier 为 null，则生成空 allowCredentials，支持 passkey/discoverable 流程。
     *
     * @return array{'challenge_id': string, 'options': array<string, mixed>}
     */
    public function startAuthentication(?string $userIdentifier = null): array
    {
        $challengeBytes = random_bytes(32);
        $challengeId = bin2hex(random_bytes(16));

        $allowCredentials = [];
        if ($userIdentifier !== null) {
            $sources = $this->credentialRepository->findAllByUserIdentifier($userIdentifier);
            foreach ($sources as $source) {
                $allowCredentials[] = $source->getPublicKeyCredentialDescriptor();
            }
        }

        $options = PublicKeyCredentialRequestOptions::create(
            challenge: $challengeBytes,
            rpId: $this->rpId,
            allowCredentials: $allowCredentials,
            userVerification: $this->userVerification,
            timeout: $this->timeout,
        );

        $serializer = $this->factory->getSerializer();
        $optionsJson = $serializer->serialize($options, 'json');

        $this->challengeStorage->store($challengeId, new WebAuthnChallenge(
            type: 'authentication',
            userIdentifier: $userIdentifier,
            challengeBytes: $challengeBytes,
            issuedAt: time(),
            metadata: ['request_options' => $optionsJson],
        ));

        return [
            'challenge_id' => $challengeId,
            'options' => json_decode($optionsJson, true, 512, JSON_THROW_ON_ERROR),
        ];
    }
}
