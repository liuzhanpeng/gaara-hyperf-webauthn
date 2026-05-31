<?php

declare(strict_types=1);

use GaaraHyperf\Exception\AuthenticationException;
use GaaraHyperf\User\UserInterface;
use GaaraHyperf\UserProvider\UserProviderInterface;
use GaaraHyperf\WebAuthn\ChallengeStorage\ChallengeStorageInterface;
use GaaraHyperf\WebAuthn\ChallengeStorage\WebAuthnChallenge;
use GaaraHyperf\WebAuthn\Credential\PublicKeyCredentialRepositoryInterface;
use GaaraHyperf\WebAuthn\Service\WebAuthnFactory;
use GaaraHyperf\WebAuthn\WebAuthnAuthenticator;
use Mockery\MockInterface;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Exception\AuthenticatorResponseVerificationException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;

function makeAuthenticator(
    ChallengeStorageInterface $storage,
    PublicKeyCredentialRepositoryInterface $repo,
    UserProviderInterface $userProvider,
    WebAuthnFactory $factory,
    int $ttl = 120,
): WebAuthnAuthenticator {
    return new WebAuthnAuthenticator(
        authenticatePath: '/webauthn/authenticate',
        challengeStorage: $storage,
        credentialRepository: $repo,
        userProvider: $userProvider,
        factory: $factory,
        challengeTtl: $ttl,
        credentialField: 'credential',
        challengeIdField: 'challenge_id',
    );
}

it('supports POST on authenticate path', function (): void {
    $auth = makeAuthenticator(
        Mockery::mock(ChallengeStorageInterface::class),
        Mockery::mock(PublicKeyCredentialRepositoryInterface::class),
        Mockery::mock(UserProviderInterface::class),
        Mockery::mock(WebAuthnFactory::class),
    );

    expect($auth->supports(makeRequest('POST', '/webauthn/authenticate')))->toBeTrue();
    expect($auth->supports(makeRequest('GET', '/webauthn/authenticate')))->toBeFalse();
    expect($auth->supports(makeRequest('POST', '/other')))->toBeFalse();
});

it('is interactive', function (): void {
    $auth = makeAuthenticator(
        Mockery::mock(ChallengeStorageInterface::class),
        Mockery::mock(PublicKeyCredentialRepositoryInterface::class),
        Mockery::mock(UserProviderInterface::class),
        Mockery::mock(WebAuthnFactory::class),
    );

    expect($auth->isInteractive())->toBeTrue();
});

it('throws when challenge_id is missing', function (): void {
    $storage = Mockery::mock(ChallengeStorageInterface::class);
    $auth = makeAuthenticator(
        $storage,
        Mockery::mock(PublicKeyCredentialRepositoryInterface::class),
        Mockery::mock(UserProviderInterface::class),
        Mockery::mock(WebAuthnFactory::class),
    );

    $request = makeRequest('POST', '/webauthn/authenticate', ['credential' => ['id' => 'abc']]);
    expect(fn () => $auth->authenticate($request))->toThrow(AuthenticationException::class, 'Missing challenge_id');
});

it('throws when credential is missing', function (): void {
    $storage = Mockery::mock(ChallengeStorageInterface::class);
    $auth = makeAuthenticator(
        $storage,
        Mockery::mock(PublicKeyCredentialRepositoryInterface::class),
        Mockery::mock(UserProviderInterface::class),
        Mockery::mock(WebAuthnFactory::class),
    );

    $request = makeRequest('POST', '/webauthn/authenticate', ['challenge_id' => 'abc123']);
    expect(fn () => $auth->authenticate($request))->toThrow(AuthenticationException::class, 'Missing or invalid credential');
});

it('throws when challenge is not found in storage', function (): void {
    $storage = Mockery::mock(ChallengeStorageInterface::class);
    $storage->shouldReceive('get')->once()->with('abc123')->andReturn(null);

    $auth = makeAuthenticator(
        $storage,
        Mockery::mock(PublicKeyCredentialRepositoryInterface::class),
        Mockery::mock(UserProviderInterface::class),
        Mockery::mock(WebAuthnFactory::class),
    );

    $request = makeRequest('POST', '/webauthn/authenticate', [
        'challenge_id' => 'abc123',
        'credential' => ['id' => 'cred', 'type' => 'public-key', 'rawId' => 'abc', 'response' => []],
    ]);

    expect(fn () => $auth->authenticate($request))->toThrow(AuthenticationException::class, 'Invalid or expired challenge');
});

it('throws and deletes challenge when challenge is expired', function (): void {
    $storage = Mockery::mock(ChallengeStorageInterface::class);
    $storage->shouldReceive('get')->once()->with('exp123')->andReturn(
        new WebAuthnChallenge('authentication', 'user-1', random_bytes(32), time() - 300, ['request_options' => '{}'])
    );
    $storage->shouldReceive('delete')->once()->with('exp123');

    $auth = makeAuthenticator(
        $storage,
        Mockery::mock(PublicKeyCredentialRepositoryInterface::class),
        Mockery::mock(UserProviderInterface::class),
        Mockery::mock(WebAuthnFactory::class),
        ttl: 120,
    );

    $request = makeRequest('POST', '/webauthn/authenticate', [
        'challenge_id' => 'exp123',
        'credential' => ['id' => 'cred', 'type' => 'public-key', 'rawId' => 'abc', 'response' => []],
    ]);

    expect(fn () => $auth->authenticate($request))->toThrow(AuthenticationException::class, 'WebAuthn challenge has expired');
});

it('throws when credential source is not found in repository', function (): void {
    $challenge = new WebAuthnChallenge(
        'authentication',
        'user-1',
        random_bytes(32),
        time(),
        ['request_options' => '{"challenge":"dGVzdA","rpId":"example.com","allowCredentials":[],"userVerification":"preferred"}']
    );

    $storage = Mockery::mock(ChallengeStorageInterface::class);
    $storage->shouldReceive('get')->once()->andReturn($challenge);

    $repo = Mockery::mock(PublicKeyCredentialRepositoryInterface::class);

    /** @var MockInterface&SerializerInterface $serializer */
    $serializer = Mockery::mock(SerializerInterface::class);

    /** @var AuthenticatorAssertionResponse&MockInterface $assertionResponse */
    $assertionResponse = Mockery::mock(AuthenticatorAssertionResponse::class);

    $pkc = PublicKeyCredential::create(null, 'public-key', 'raw-binary-id', $assertionResponse);

    $serializer->shouldReceive('deserialize')
        ->once()
        ->with(Mockery::type('string'), PublicKeyCredential::class, 'json')
        ->andReturn($pkc);

    $factory = Mockery::mock(WebAuthnFactory::class);
    $factory->shouldReceive('getSerializer')->andReturn($serializer);

    $repo->shouldReceive('findByCredentialId')->with('raw-binary-id')->andReturn(null);

    $auth = makeAuthenticator($storage, $repo, Mockery::mock(UserProviderInterface::class), $factory);

    $request = makeRequest('POST', '/webauthn/authenticate', [
        'challenge_id' => 'c1',
        'credential' => ['id' => 'Y3JlZA', 'type' => 'public-key', 'rawId' => 'Y3JlZA', 'response' => ['authenticatorData' => 'dGVzdA', 'signature' => 'dGVzdA', 'clientDataJSON' => 'dGVzdA']],
    ]);

    expect(fn () => $auth->authenticate($request))->toThrow(AuthenticationException::class, 'Unknown credential');
});

it('throws when assertion validation fails', function (): void {
    $requestOptionsJson = json_encode([
        'challenge' => base64_encode(random_bytes(32)),
        'rpId' => 'example.com',
        'allowCredentials' => [],
        'userVerification' => 'preferred',
    ]);
    $challenge = new WebAuthnChallenge('authentication', 'user-1', random_bytes(32), time(), ['request_options' => $requestOptionsJson]);

    $storage = Mockery::mock(ChallengeStorageInterface::class);
    $storage->shouldReceive('get')->andReturn($challenge);

    /** @var MockInterface&SerializerInterface $serializer */
    $serializer = Mockery::mock(SerializerInterface::class);

    /** @var AuthenticatorAssertionResponse&MockInterface $assertionResponse */
    $assertionResponse = Mockery::mock(AuthenticatorAssertionResponse::class);

    $pkc = PublicKeyCredential::create(null, 'public-key', 'raw-id', $assertionResponse);

    /** @var MockInterface&PublicKeyCredentialSource $source */
    $source = Mockery::mock(PublicKeyCredentialSource::class);
    $source->userHandle = 'user-1';

    $requestOptions = PublicKeyCredentialRequestOptions::create(random_bytes(32), 'example.com');

    $serializer->shouldReceive('deserialize')
        ->with(Mockery::type('string'), PublicKeyCredential::class, 'json')
        ->andReturn($pkc);
    $serializer->shouldReceive('deserialize')
        ->with($requestOptionsJson, PublicKeyCredentialRequestOptions::class, 'json')
        ->andReturn($requestOptions);

    /** @var AuthenticatorAssertionResponseValidator&MockInterface $validator */
    $validator = Mockery::mock(AuthenticatorAssertionResponseValidator::class);
    $validator->shouldReceive('check')->andThrow(
        AuthenticatorResponseVerificationException::create('Signature verification failed')
    );

    $factory = Mockery::mock(WebAuthnFactory::class);
    $factory->shouldReceive('getSerializer')->andReturn($serializer);
    $factory->shouldReceive('createAssertionValidator')->andReturn($validator);

    $repo = Mockery::mock(PublicKeyCredentialRepositoryInterface::class);
    $repo->shouldReceive('findByCredentialId')->andReturn($source);

    $auth = makeAuthenticator($storage, $repo, Mockery::mock(UserProviderInterface::class), $factory);

    $request = makeRequest('POST', '/webauthn/authenticate', [
        'challenge_id' => 'c1',
        'credential' => ['id' => 'abc', 'type' => 'public-key', 'rawId' => 'abc', 'response' => ['authenticatorData' => 'dGVzdA', 'signature' => 'dGVzdA', 'clientDataJSON' => 'dGVzdA']],
    ], 'example.com');

    expect(fn () => $auth->authenticate($request))->toThrow(AuthenticationException::class, 'WebAuthn assertion verification failed');
});

it('returns Passport on successful authentication', function (): void {
    $requestOptionsJson = json_encode([
        'challenge' => base64_encode(random_bytes(32)),
        'rpId' => 'example.com',
        'allowCredentials' => [],
        'userVerification' => 'preferred',
    ]);
    $challenge = new WebAuthnChallenge('authentication', 'user-1', random_bytes(32), time(), ['request_options' => $requestOptionsJson]);

    $storage = Mockery::mock(ChallengeStorageInterface::class);
    $storage->shouldReceive('get')->andReturn($challenge);
    $storage->shouldReceive('delete')->once();

    /** @var MockInterface&SerializerInterface $serializer */
    $serializer = Mockery::mock(SerializerInterface::class);

    /** @var AuthenticatorAssertionResponse&MockInterface $assertionResponse */
    $assertionResponse = Mockery::mock(AuthenticatorAssertionResponse::class);

    $pkc = PublicKeyCredential::create(null, 'public-key', 'raw-id', $assertionResponse);

    /** @var MockInterface&PublicKeyCredentialSource $source */
    $source = Mockery::mock(PublicKeyCredentialSource::class);
    $source->userHandle = 'user-1';

    /** @var MockInterface&PublicKeyCredentialSource $updatedSource */
    $updatedSource = Mockery::mock(PublicKeyCredentialSource::class);
    $updatedSource->userHandle = 'user-1';

    $requestOptions = PublicKeyCredentialRequestOptions::create(random_bytes(32), 'example.com');

    $serializer->shouldReceive('deserialize')
        ->with(Mockery::type('string'), PublicKeyCredential::class, 'json')
        ->andReturn($pkc);
    $serializer->shouldReceive('deserialize')
        ->with($requestOptionsJson, PublicKeyCredentialRequestOptions::class, 'json')
        ->andReturn($requestOptions);

    /** @var AuthenticatorAssertionResponseValidator&MockInterface $validator */
    $validator = Mockery::mock(AuthenticatorAssertionResponseValidator::class);
    $validator->shouldReceive('check')->once()->andReturn($updatedSource);

    $factory = Mockery::mock(WebAuthnFactory::class);
    $factory->shouldReceive('getSerializer')->andReturn($serializer);
    $factory->shouldReceive('createAssertionValidator')->andReturn($validator);

    $repo = Mockery::mock(PublicKeyCredentialRepositoryInterface::class);
    $repo->shouldReceive('findByCredentialId')->andReturn($source);
    $repo->shouldReceive('save')->once()->with($updatedSource);

    /** @var MockInterface&UserInterface $user */
    $user = Mockery::mock(UserInterface::class);
    $user->shouldReceive('getIdentifier')->andReturn('user-1');

    $userProvider = Mockery::mock(UserProviderInterface::class);
    $userProvider->shouldReceive('findByIdentifier')->with('user-1')->andReturn($user);

    $auth = makeAuthenticator($storage, $repo, $userProvider, $factory);

    $request = makeRequest('POST', '/webauthn/authenticate', [
        'challenge_id' => 'c1',
        'credential' => ['id' => 'abc', 'type' => 'public-key', 'rawId' => 'abc', 'response' => ['authenticatorData' => 'dGVzdA', 'signature' => 'dGVzdA', 'clientDataJSON' => 'dGVzdA']],
    ], 'example.com');

    $passport = $auth->authenticate($request);
    expect($passport->getUserIdentifier())->toBe('user-1');
});
