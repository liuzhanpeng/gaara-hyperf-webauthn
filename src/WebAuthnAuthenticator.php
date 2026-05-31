<?php

declare(strict_types=1);

namespace GaaraHyperf\WebAuthn;

use GaaraHyperf\Authenticator\AbstractAuthenticator;
use GaaraHyperf\Authenticator\AuthenticationFailureHandlerInterface;
use GaaraHyperf\Authenticator\AuthenticationSuccessHandlerInterface;
use GaaraHyperf\Exception\AuthenticationException;
use GaaraHyperf\Passport\Passport;
use GaaraHyperf\UserProvider\UserProviderInterface;
use GaaraHyperf\WebAuthn\ChallengeStorage\ChallengeStorageInterface;
use GaaraHyperf\WebAuthn\Credential\PublicKeyCredentialRepositoryInterface;
use GaaraHyperf\WebAuthn\Service\WebAuthnFactory;
use GaaraHyperf\WebAuthn\Service\WebAuthnManager;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * WebAuthn 断言认证器.
 *
 * 处理 POST authenticate_path 的登录断言验证请求：
 *   1. 根据请求中的 challenge_id 检索挑战数据（由前端 startAuthentication 后存储）
 *   2. 校验挑战 TTL
 *   3. 根据 credential.id 找到存储的 PublicKeyCredentialSource
 *   4. 调用 AuthenticatorAssertionResponseValidator 验证断言签名
 *   5. 更新 sign count，删除挑战
 *   6. 返回 Passport，由 Guard 创建最终的 AuthenticatedToken
 *
 * 注意：注册流程（startRegistration / finishRegistration）由 {@see WebAuthnManager}
 * 提供，需在应用自己的 Controller 中调用。
 */
class WebAuthnAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private string $authenticatePath,
        private ChallengeStorageInterface $challengeStorage,
        private PublicKeyCredentialRepositoryInterface $credentialRepository,
        private UserProviderInterface $userProvider,
        private WebAuthnFactory $factory,
        private int $challengeTtl,
        private string $credentialField,
        private string $challengeIdField,
        ?AuthenticationSuccessHandlerInterface $successHandler = null,
        ?AuthenticationFailureHandlerInterface $failureHandler = null,
    ) {
        parent::__construct($successHandler, $failureHandler);
    }

    public function supports(ServerRequestInterface $request): bool
    {
        return $request->getMethod() === 'POST'
            && $request->getUri()->getPath() === $this->authenticatePath;
    }

    public function authenticate(ServerRequestInterface $request): Passport
    {
        $body = (array) $request->getParsedBody();

        $challengeId = (string) ($body[$this->challengeIdField] ?? '');
        $credentialData = $body[$this->credentialField] ?? null;

        if ($challengeId === '') {
            throw new AuthenticationException('Missing challenge_id');
        }

        if (! is_array($credentialData) || empty($credentialData)) {
            throw new AuthenticationException('Missing or invalid credential');
        }

        // 检索并校验挑战
        $challenge = $this->challengeStorage->get($challengeId);
        if ($challenge === null) {
            throw new AuthenticationException('Invalid or expired challenge');
        }
        if ($challenge->isExpired($this->challengeTtl)) {
            $this->challengeStorage->delete($challengeId);
            throw new AuthenticationException('WebAuthn challenge has expired');
        }
        if ($challenge->type !== 'authentication') {
            throw new AuthenticationException('Challenge type mismatch: expected authentication');
        }

        // 反序列化前端提交的 PublicKeyCredential
        $serializer = $this->factory->getSerializer();
        try {
            /** @var PublicKeyCredential $credential */
            $credential = $serializer->deserialize(
                json_encode($credentialData, JSON_THROW_ON_ERROR),
                PublicKeyCredential::class,
                'json'
            );
        } catch (Throwable $e) {
            throw new AuthenticationException('Invalid credential JSON: ' . $e->getMessage());
        }

        if (! $credential->response instanceof AuthenticatorAssertionResponse) {
            throw new AuthenticationException('Invalid credential response type: expected assertion');
        }

        // 根据凭据 ID 查找存储的凭据源
        $credentialSource = $this->credentialRepository->findByCredentialId($credential->rawId);
        if ($credentialSource === null) {
            throw new AuthenticationException('Unknown credential');
        }

        // 还原请求选项
        $requestOptions = $serializer->deserialize(
            $challenge->metadata['request_options'],
            PublicKeyCredentialRequestOptions::class,
            'json'
        );

        // 确定用户标识符：优先使用挑战中的（已知用户流程），否则使用凭据源中的用户句柄（discoverable 流程）
        $userIdentifier = $challenge->userIdentifier ?? $credentialSource->userHandle;

        // 验证断言
        try {
            $updatedSource = $this->factory->createAssertionValidator()->check(
                credentialId: $credentialSource,
                authenticatorAssertionResponse: $credential->response,
                publicKeyCredentialRequestOptions: $requestOptions,
                request: $request->getUri()->getHost(),
                userHandle: $credentialSource->userHandle,
            );
        } catch (AuthenticatorResponseVerificationException $e) {
            throw new AuthenticationException(
                'WebAuthn assertion verification failed: ' . $e->getMessage(),
                userIdentifier: $userIdentifier,
            );
        }

        // 更新 sign count 并删除挑战（一次性使用）
        $this->credentialRepository->save($updatedSource);
        $this->challengeStorage->delete($challengeId);

        // 加载用户
        $user = $this->userProvider->findByIdentifier($userIdentifier);
        if ($user === null) {
            throw new AuthenticationException(
                message: 'User not found',
                userIdentifier: $userIdentifier,
            );
        }

        return new Passport(
            $userIdentifier,
            fn () => $user,
        );
    }

    /**
     * WebAuthn 登录属于交互式认证，验证成功后需要持久化令牌（如写入 Session）.
     */
    public function isInteractive(): bool
    {
        return true;
    }
}
