<?php

declare(strict_types=1);

use GaaraHyperf\WebAuthn\ChallengeStorage\ChallengeStorageInterface;
use GaaraHyperf\WebAuthn\ChallengeStorage\WebAuthnChallenge;
use GaaraHyperf\WebAuthn\Credential\PublicKeyCredentialRepositoryInterface;
use GaaraHyperf\WebAuthn\Service\WebAuthnFactory;
use GaaraHyperf\WebAuthn\Service\WebAuthnManager;
use Mockery\MockInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

function makeManager(
    ChallengeStorageInterface $storage,
    PublicKeyCredentialRepositoryInterface $repo,
    WebAuthnFactory $factory,
    int $ttl = 120,
): WebAuthnManager {
    return new WebAuthnManager(
        rpName: 'Test App',
        rpId: 'example.com',
        challengeTtl: $ttl,
        timeout: 60000,
        userVerification: 'preferred',
        challengeStorage: $storage,
        credentialRepository: $repo,
        factory: $factory,
    );
}

it('startRegistration returns challenge_id and serialized options', function (): void {
    /** @var ChallengeStorageInterface&MockInterface $storage */
    $storage = Mockery::mock(ChallengeStorageInterface::class);
    $storage->shouldReceive('store')->once()->withArgs(function (string $id, WebAuthnChallenge $challenge): bool {
        return $challenge->type === 'registration'
            && $challenge->userIdentifier === 'user-1'
            && strlen($challenge->challengeBytes) === 32
            && isset($challenge->metadata['creation_options']);
    });

    /** @var MockInterface&SerializerInterface $serializer */
    $serializer = Mockery::mock(SerializerInterface::class);
    $serializer->shouldReceive('serialize')
        ->once()
        ->with(Mockery::type(PublicKeyCredentialCreationOptions::class), 'json')
        ->andReturn('{"challenge":"dGVzdA"}');

    $factory = Mockery::mock(WebAuthnFactory::class);
    $factory->shouldReceive('getSerializer')->andReturn($serializer);

    $manager = makeManager($storage, Mockery::mock(PublicKeyCredentialRepositoryInterface::class), $factory);
    $user = makeWebAuthnUser('user-1', 'Alice');

    $result = $manager->startRegistration($user);

    expect($result)->toHaveKey('challenge_id')
        ->and($result)->toHaveKey('options')
        ->and($result['challenge_id'])->toBeString()->toHaveLength(32)  // 16 bytes → 32 hex chars
        ->and($result['options'])->toBeArray();
});

it('startAuthentication returns challenge_id and options with known user', function (): void {
    /** @var MockInterface&PublicKeyCredentialSource $src */
    $src = Mockery::mock(PublicKeyCredentialSource::class);
    $descriptor = Mockery::mock(PublicKeyCredentialDescriptor::class);
    $src->shouldReceive('getPublicKeyCredentialDescriptor')->andReturn($descriptor);

    $repo = Mockery::mock(PublicKeyCredentialRepositoryInterface::class);
    $repo->shouldReceive('findAllByUserIdentifier')->with('user-1')->andReturn([$src]);

    /** @var ChallengeStorageInterface&MockInterface $storage */
    $storage = Mockery::mock(ChallengeStorageInterface::class);
    $storage->shouldReceive('store')->once()->withArgs(function (string $id, WebAuthnChallenge $challenge): bool {
        return $challenge->type === 'authentication'
            && $challenge->userIdentifier === 'user-1'
            && isset($challenge->metadata['request_options']);
    });

    /** @var MockInterface&SerializerInterface $serializer */
    $serializer = Mockery::mock(SerializerInterface::class);
    $serializer->shouldReceive('serialize')
        ->once()
        ->with(Mockery::type(PublicKeyCredentialRequestOptions::class), 'json')
        ->andReturn('{"challenge":"dGVzdA","rpId":"example.com"}');

    $factory = Mockery::mock(WebAuthnFactory::class);
    $factory->shouldReceive('getSerializer')->andReturn($serializer);

    $manager = makeManager($storage, $repo, $factory);
    $result = $manager->startAuthentication('user-1');

    expect($result)->toHaveKey('challenge_id')
        ->and($result)->toHaveKey('options')
        ->and($result['challenge_id'])->toBeString()
        ->and($result['options'])->toBeArray();
});

it('startAuthentication returns empty allowCredentials for discoverable flow', function (): void {
    $repo = Mockery::mock(PublicKeyCredentialRepositoryInterface::class);
    // findAllByUserIdentifier should NOT be called when userIdentifier is null

    /** @var ChallengeStorageInterface&MockInterface $storage */
    $storage = Mockery::mock(ChallengeStorageInterface::class);
    $storage->shouldReceive('store')->once()->withArgs(function (string $id, WebAuthnChallenge $challenge): bool {
        return $challenge->type === 'authentication'
            && $challenge->userIdentifier === null;
    });

    /** @var MockInterface&SerializerInterface $serializer */
    $serializer = Mockery::mock(SerializerInterface::class);
    $serializer->shouldReceive('serialize')
        ->once()
        ->with(Mockery::type(PublicKeyCredentialRequestOptions::class), 'json')
        ->andReturn('{"challenge":"dGVzdA"}');

    $factory = Mockery::mock(WebAuthnFactory::class);
    $factory->shouldReceive('getSerializer')->andReturn($serializer);

    $manager = makeManager($storage, $repo, $factory);
    $result = $manager->startAuthentication(null);

    expect($result)->toHaveKey('challenge_id')
        ->and($result)->toHaveKey('options');
});

it('finishRegistration throws on invalid challenge', function (): void {
    $storage = Mockery::mock(ChallengeStorageInterface::class);
    $storage->shouldReceive('get')->andReturn(null);

    $factory = Mockery::mock(WebAuthnFactory::class);
    $manager = makeManager($storage, Mockery::mock(PublicKeyCredentialRepositoryInterface::class), $factory);

    expect(fn () => $manager->finishRegistration('bad-id', [], 'example.com'))
        ->toThrow(RuntimeException::class, 'Invalid or expired WebAuthn challenge');
});

it('finishRegistration throws on expired challenge', function (): void {
    $expiredChallenge = new WebAuthnChallenge('registration', 'user-1', random_bytes(32), time() - 300, ['creation_options' => '{}']);

    $storage = Mockery::mock(ChallengeStorageInterface::class);
    $storage->shouldReceive('get')->andReturn($expiredChallenge);
    $storage->shouldReceive('delete')->once();

    $factory = Mockery::mock(WebAuthnFactory::class);
    $manager = makeManager($storage, Mockery::mock(PublicKeyCredentialRepositoryInterface::class), $factory, ttl: 120);

    expect(fn () => $manager->finishRegistration('exp-id', [], 'example.com'))
        ->toThrow(RuntimeException::class, 'WebAuthn challenge has expired');
});

it('finishRegistration throws on challenge type mismatch', function (): void {
    $authChallenge = new WebAuthnChallenge('authentication', 'user-1', random_bytes(32), time(), ['request_options' => '{}']);

    $storage = Mockery::mock(ChallengeStorageInterface::class);
    $storage->shouldReceive('get')->andReturn($authChallenge);

    $factory = Mockery::mock(WebAuthnFactory::class);
    $manager = makeManager($storage, Mockery::mock(PublicKeyCredentialRepositoryInterface::class), $factory);

    expect(fn () => $manager->finishRegistration('c1', [], 'example.com'))
        ->toThrow(RuntimeException::class, 'Challenge type mismatch');
});
