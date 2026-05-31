<?php

declare(strict_types=1);

namespace GaaraHyperf\WebAuthn\Service;

use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

/**
 * WebAuthn 组件工厂.
 *
 * 构建 webauthn-lib 所需的验证器和序列化器实例。
 * 默认使用 none attestation，内置 ES256 + RS256 算法支持。
 */
class WebAuthnFactory
{
    private readonly AttestationStatementSupportManager $attestationSupportManager;

    private readonly CeremonyStepManagerFactory $ceremonyFactory;

    private readonly SerializerInterface $serializer;

    public function __construct()
    {
        $this->attestationSupportManager = new AttestationStatementSupportManager([
            new NoneAttestationStatementSupport(),
        ]);
        $this->ceremonyFactory = new CeremonyStepManagerFactory();
        $this->serializer = (new WebauthnSerializerFactory($this->attestationSupportManager))->create();
    }

    public function createAttestationValidator(): AuthenticatorAttestationResponseValidator
    {
        return new AuthenticatorAttestationResponseValidator(
            ceremonyStepManager: $this->ceremonyFactory->creationCeremony(),
        );
    }

    public function createAssertionValidator(): AuthenticatorAssertionResponseValidator
    {
        return new AuthenticatorAssertionResponseValidator(
            ceremonyStepManager: $this->ceremonyFactory->requestCeremony(),
        );
    }

    public function getSerializer(): SerializerInterface
    {
        return $this->serializer;
    }
}
