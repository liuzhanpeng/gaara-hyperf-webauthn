<?php

declare(strict_types=1);

namespace GaaraHyperf\WebAuthn;

use GaaraHyperf\Authenticator\AuthenticatorInterface;
use GaaraHyperf\Authenticator\Builder\AbstractAuthenticatorBuilder;
use GaaraHyperf\UserProvider\UserProviderInterface;
use GaaraHyperf\WebAuthn\ChallengeStorage\ChallengeStorageFactory;
use GaaraHyperf\WebAuthn\Credential\PublicKeyCredentialRepositoryInterface;
use GaaraHyperf\WebAuthn\Service\WebAuthnFactory;
use GaaraHyperf\WebAuthn\Service\WebAuthnManager;
use InvalidArgumentException;
use Symfony\Component\EventDispatcher\EventDispatcher;

/**
 * WebAuthn 认证器构建器.
 *
 * 在 auth.php 的 authenticators 中配置 webauthn 即可启用：
 *
 * ```php
 * 'authenticators' => [
 *     'webauthn' => [
 *         'authenticate_path'   => '/webauthn/authenticate',
 *         'rp_name'             => 'My App',
 *         'rp_id'               => 'example.com',
 *         'challenge_ttl'       => 120,
 *         'credential_field'    => 'credential',
 *         'challenge_id_field'  => 'challenge_id',
 *         'user_verification'   => 'preferred',
 *         'timeout'             => 60000,
 *         'storage'             => ['type' => 'session'],
 *     ],
 * ],
 * ```
 *
 * 构建完成后会同时在容器中绑定 {@see WebAuthnManager}，
 * 以便应用注入到自己的 Controller 中调用 startRegistration / finishRegistration / startAuthentication。
 */
class WebAuthnAuthenticatorBuilder extends AbstractAuthenticatorBuilder
{
    public function create(array $options, UserProviderInterface $userProvider, EventDispatcher $eventDispatcher): AuthenticatorInterface
    {
        $options = $options + [
            'authenticate_path' => '/webauthn/authenticate',
            'rp_name' => 'My App',
            'rp_id' => null,
            'challenge_ttl' => 120,
            'credential_field' => 'credential',
            'challenge_id_field' => 'challenge_id',
            'user_verification' => 'preferred',
            'timeout' => 60000,
            'storage' => ['type' => 'session'],
        ];

        if (empty($options['rp_id'])) {
            throw new InvalidArgumentException('WebAuthn authenticator requires "rp_id" (e.g. "example.com").');
        }

        if (! $this->container->has(PublicKeyCredentialRepositoryInterface::class)) {
            throw new InvalidArgumentException(sprintf(
                'WebAuthn authenticator requires a container binding for "%s". '
                . 'Please bind your credential repository implementation in your ConfigProvider.',
                PublicKeyCredentialRepositoryInterface::class
            ));
        }

        $credentialRepository = $this->container->get(PublicKeyCredentialRepositoryInterface::class);
        $challengeTtl = (int) $options['challenge_ttl'];

        $challengeStorage = $this->container
            ->get(ChallengeStorageFactory::class)
            ->create($options['storage'], $challengeTtl);

        $factory = new WebAuthnFactory();

        // 绑定 WebAuthnManager 到容器，供应用 Controller 注入使用
        if (! $this->container->has(WebAuthnManager::class)) {
            $manager = new WebAuthnManager(
                rpName: (string) $options['rp_name'],
                rpId: (string) $options['rp_id'],
                challengeTtl: $challengeTtl,
                timeout: isset($options['timeout']) ? (int) $options['timeout'] : null,
                userVerification: (string) $options['user_verification'],
                challengeStorage: $challengeStorage,
                credentialRepository: $credentialRepository,
                factory: $factory,
            );
            $this->container->set(WebAuthnManager::class, $manager);
        }

        return new WebAuthnAuthenticator(
            authenticatePath: (string) $options['authenticate_path'],
            challengeStorage: $challengeStorage,
            credentialRepository: $credentialRepository,
            userProvider: $userProvider,
            factory: $factory,
            challengeTtl: $challengeTtl,
            credentialField: (string) $options['credential_field'],
            challengeIdField: (string) $options['challenge_id_field'],
            successHandler: $this->createSuccessHandler($options),
            failureHandler: $this->createFailureHandler($options),
        );
    }
}
