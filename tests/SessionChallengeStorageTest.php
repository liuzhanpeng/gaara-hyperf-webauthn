<?php

declare(strict_types=1);

use GaaraHyperf\WebAuthn\ChallengeStorage\SessionChallengeStorage;
use GaaraHyperf\WebAuthn\ChallengeStorage\WebAuthnChallenge;
use Hyperf\Contract\SessionInterface;

it('stores, retrieves, and deletes a challenge via session', function (): void {
    $session = Mockery::mock(SessionInterface::class);
    $storage = new SessionChallengeStorage($session);

    $bytes = random_bytes(32);
    $challenge = new WebAuthnChallenge('authentication', 'user-1', $bytes, time(), ['request_options' => '{}']);
    $key = '_gaara_webauthn_challenge_abc123';

    $session->shouldReceive('set')->once()->with($key, Mockery::type('string'));
    $session->shouldReceive('get')->once()->with($key)->andReturnUsing(function () use ($challenge): string {
        return json_encode([
            'type' => $challenge->type,
            'user_identifier' => $challenge->userIdentifier,
            'challenge_bytes' => base64_encode($challenge->challengeBytes),
            'issued_at' => $challenge->issuedAt,
            'metadata' => $challenge->metadata,
        ]);
    });
    $session->shouldReceive('remove')->once()->with($key);

    $storage->store('abc123', $challenge);

    $retrieved = $storage->get('abc123');
    expect($retrieved)->toBeInstanceOf(WebAuthnChallenge::class)
        ->and($retrieved->type)->toBe('authentication')
        ->and($retrieved->userIdentifier)->toBe('user-1')
        ->and($retrieved->challengeBytes)->toBe($bytes)
        ->and($retrieved->metadata)->toBe(['request_options' => '{}']);

    $storage->delete('abc123');
});

it('stores challenge with null userIdentifier for discoverable flow', function (): void {
    $session = Mockery::mock(SessionInterface::class);
    $storage = new SessionChallengeStorage($session);

    $challenge = new WebAuthnChallenge('authentication', null, random_bytes(32), time());
    $key = '_gaara_webauthn_challenge_xyz';

    $session->shouldReceive('set')->once()->with($key, Mockery::type('string'));
    $session->shouldReceive('get')->once()->with($key)->andReturnUsing(function () use ($challenge): string {
        return json_encode([
            'type' => $challenge->type,
            'user_identifier' => null,
            'challenge_bytes' => base64_encode($challenge->challengeBytes),
            'issued_at' => $challenge->issuedAt,
            'metadata' => [],
        ]);
    });

    $storage->store('xyz', $challenge);
    $retrieved = $storage->get('xyz');

    expect($retrieved->userIdentifier)->toBeNull();
});

it('returns null when session key is missing', function (): void {
    $session = Mockery::mock(SessionInterface::class);
    $session->shouldReceive('get')->once()->andReturn(null);

    $storage = new SessionChallengeStorage($session);
    expect($storage->get('nonexistent'))->toBeNull();
});

it('returns null when session value is corrupted', function (): void {
    $session = Mockery::mock(SessionInterface::class);
    $session->shouldReceive('get')->once()->andReturn('not-valid-json');

    $storage = new SessionChallengeStorage($session);
    expect($storage->get('bad'))->toBeNull();
});

it('returns null when session value is missing required fields', function (): void {
    $session = Mockery::mock(SessionInterface::class);
    $session->shouldReceive('get')->once()->andReturn(json_encode(['type' => 'authentication']));

    $storage = new SessionChallengeStorage($session);
    expect($storage->get('incomplete'))->toBeNull();
});
