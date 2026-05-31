<?php

declare(strict_types=1);

use GaaraHyperf\WebAuthn\WebAuthnUserInterface;
use Mockery\MockInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

afterEach(function (): void {
    Mockery::close();
});

function makeRequest(string $method = 'GET', string $path = '/', array $body = [], string $host = 'example.com'): ServerRequestInterface
{
    /** @var MockInterface&ServerRequestInterface $request */
    $request = Mockery::mock(ServerRequestInterface::class);
    /** @var MockInterface&UriInterface $uri */
    $uri = Mockery::mock(UriInterface::class);

    $request->shouldReceive('getMethod')->andReturn($method);
    $request->shouldReceive('getUri')->andReturn($uri);
    $uri->shouldReceive('getPath')->andReturn($path);
    $uri->shouldReceive('getHost')->andReturn($host);

    if (! empty($body)) {
        $request->shouldReceive('getParsedBody')->andReturn($body);
    }

    return $request;
}

function makeWebAuthnUser(string $identifier = 'user-1', string $displayName = 'Test User'): WebAuthnUserInterface
{
    /** @var MockInterface&WebAuthnUserInterface $user */
    $user = Mockery::mock(WebAuthnUserInterface::class);
    $user->shouldReceive('getIdentifier')->andReturn($identifier);
    $user->shouldReceive('getWebAuthnDisplayName')->andReturn($displayName);

    return $user;
}
