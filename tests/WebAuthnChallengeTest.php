<?php

declare(strict_types=1);

use GaaraHyperf\WebAuthn\ChallengeStorage\WebAuthnChallenge;

it('reports not expired when within ttl', function (): void {
    $challenge = new WebAuthnChallenge('authentication', 'user-1', random_bytes(32), time());
    expect($challenge->isExpired(120))->toBeFalse();
});

it('reports expired when outside ttl', function (): void {
    $challenge = new WebAuthnChallenge('registration', null, random_bytes(32), time() - 300);
    expect($challenge->isExpired(120))->toBeTrue();
});

it('stores all properties correctly', function (): void {
    $bytes = random_bytes(32);
    $meta = ['creation_options' => '{"challenge":"abc"}'];
    $now = time();

    $challenge = new WebAuthnChallenge('registration', 'user-42', $bytes, $now, $meta);

    expect($challenge->type)->toBe('registration')
        ->and($challenge->userIdentifier)->toBe('user-42')
        ->and($challenge->challengeBytes)->toBe($bytes)
        ->and($challenge->issuedAt)->toBe($now)
        ->and($challenge->metadata)->toBe($meta);
});

it('allows null userIdentifier for discoverable flow', function (): void {
    $challenge = new WebAuthnChallenge('authentication', null, random_bytes(32), time());
    expect($challenge->userIdentifier)->toBeNull();
});
