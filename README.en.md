# gaara-hyperf-webauthn

WebAuthn (FIDO2 Passkey) authenticator extension for [gaara-hyperf](https://github.com/lzpeng/gaara-hyperf).

> 中文文档请查看 [README.md](README.md)

## Features

- Complete WebAuthn registration and authentication flow
- Passkey (discoverable credential) support for username-less login
- Challenge storage: Session (web) / Redis (API)
- Follows gaara-hyperf extension patterns
- Compatible with `web-auth/webauthn-lib ^4.8`

---

## Installation

```bash
composer require lzpeng/gaara-hyperf-webauthn
```

### Requirements

- PHP >= 8.1
- `lzpeng/gaara-hyperf: dev-master`
- `web-auth/webauthn-lib: ^4.8`
- `symfony/serializer: ^6.4|^7.0`
- `symfony/property-info: ^6.4|^7.0`
- App must bind `PublicKeyCredentialRepositoryInterface` in the container

---

## Quick Start

### 1. Implement the User model

```php
use GaaraHyperf\WebAuthn\WebAuthnUserInterface;

class User implements WebAuthnUserInterface
{
    public function getIdentifier(): string
    {
        return (string) $this->id; // used as the WebAuthn user handle — prefer an immutable ID (UUID / integer)
    }

    public function getWebAuthnDisplayName(): string
    {
        return $this->name; // shown in the authenticator UI only, does not affect security
    }
}
```

### 2. Implement the Credential Repository

```php
use GaaraHyperf\WebAuthn\Credential\PublicKeyCredentialRepositoryInterface;
use Webauthn\PublicKeyCredentialSource;

class CredentialRepository implements PublicKeyCredentialRepositoryInterface
{
    public function findByCredentialId(string $credentialId): ?PublicKeyCredentialSource
    {
        // query by binary credentialId
        $row = DB::table('webauthn_credentials')
            ->where('credential_id', base64_encode($credentialId))
            ->first();
        if (!$row) return null;
        return PublicKeyCredentialSource::createFromArray(json_decode($row->data, true));
    }

    public function findAllByUserIdentifier(string $userIdentifier): array
    {
        return DB::table('webauthn_credentials')
            ->where('user_identifier', $userIdentifier)
            ->get()
            ->map(fn ($r) => PublicKeyCredentialSource::createFromArray(json_decode($r->data, true)))
            ->all();
    }

    public function save(PublicKeyCredentialSource $source): void
    {
        DB::table('webauthn_credentials')->updateOrInsert(
            ['credential_id' => base64_encode($source->publicKeyCredentialId)],
            [
                'user_identifier' => $source->userHandle,
                'data'            => json_encode($source->jsonSerialize()),
                'updated_at'      => now(),
            ]
        );
    }
}
```

> **Tip**: the credentials table should have at least `credential_id` (unique index), `user_identifier` (index), `data` (JSON column), and `updated_at`.

### 3. Bind the dependency

In your application's `ConfigProvider` or `AppServiceProvider`:

```php
use GaaraHyperf\WebAuthn\Credential\PublicKeyCredentialRepositoryInterface;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => [
                PublicKeyCredentialRepositoryInterface::class => CredentialRepository::class,
            ],
        ];
    }
}
```

### 4. Configure the authenticator

In the Guard configuration in `publish/auth.php`:

```php
'guards' => [
    'web' => [
        'user_provider' => [...],
        'authenticators' => [
            'webauthn' => [
                'authenticate_path'  => '/webauthn/authenticate', // POST assertion endpoint
                'rp_name'            => 'My App',
                'rp_id'              => 'example.com',            // must match the client origin
                'challenge_ttl'      => 120,                      // seconds
                'credential_field'   => 'credential',
                'challenge_id_field' => 'challenge_id',
                'user_verification'  => 'preferred',              // required | preferred | discouraged
                'timeout'            => 60000,                    // milliseconds
                'storage'            => ['type' => 'session'],    // or ['type' => 'redis', 'ttl' => 300]
            ],
        ],
    ],
],
```

### 5. Implement registration controllers

Registration (generating options + verifying the response) is handled by the `WebAuthnManager` service injected into your own controller:

```php
use GaaraHyperf\WebAuthn\Service\WebAuthnManager;
use GaaraHyperf\WebAuthn\WebAuthnUserInterface;

class WebAuthnController
{
    public function __construct(
        private WebAuthnManager $manager,
    ) {}

    // Step 1: generate registration options (called before navigator.credentials.create())
    #[PostMapping('/webauthn/register/options')]
    public function registrationOptions(): array
    {
        /** @var WebAuthnUserInterface $user */
        $user = auth('web')->user();
        return $this->manager->startRegistration($user);
        // returns: {'challenge_id': '...', 'options': {...PublicKeyCredentialCreationOptions...}}
    }

    // Step 2: finish registration (client submits the navigator.credentials.create() result)
    #[PostMapping('/webauthn/register/verify')]
    public function registrationVerify(RequestInterface $request): array
    {
        $body   = $request->getParsedBody();
        $source = $this->manager->finishRegistration(
            challengeId:    $body['challenge_id'],
            credentialData: $body['credential'],
            host:           $request->getUri()->getHost(),
        );
        return ['status' => 'ok', 'credential_id' => base64_encode($source->publicKeyCredentialId)];
    }

    // Step 3: generate authentication options (called before navigator.credentials.get())
    #[PostMapping('/webauthn/login/options')]
    public function loginOptions(RequestInterface $request): array
    {
        $body = $request->getParsedBody();
        // pass a userIdentifier for known-user flow; pass null for Passkey (discoverable) flow
        return $this->manager->startAuthentication($body['user_identifier'] ?? null);
        // returns: {'challenge_id': '...', 'options': {...PublicKeyCredentialRequestOptions...}}
    }

    // Step 4: assertion verification is handled automatically by WebAuthnAuthenticator
    // POST /webauthn/authenticate  ← authenticate_path config key
    // body: {'challenge_id': '...', 'credential': {...navigator.credentials.get() result...}}
}
```

### 6. Frontend integration example

```javascript
// --- Registration ---
const optionsResp = await fetch('/webauthn/register/options', { method: 'POST' });
const { challenge_id, options } = await optionsResp.json();

// convert base64url strings to ArrayBuffer (requires a helper)
options.challenge = base64urlToBuffer(options.challenge);
options.user.id   = base64urlToBuffer(options.user.id);

const credential = await navigator.credentials.create({ publicKey: options });

await fetch('/webauthn/register/verify', {
  method: 'POST',
  body: JSON.stringify({ challenge_id, credential: serializeCredential(credential) }),
  headers: { 'Content-Type': 'application/json' },
});

// --- Authentication ---
const loginResp = await fetch('/webauthn/login/options', {
  method: 'POST',
  body: JSON.stringify({ user_identifier: userId }),  // pass null for Passkey flow
  headers: { 'Content-Type': 'application/json' },
});
const { challenge_id, options: reqOptions } = await loginResp.json();
reqOptions.challenge = base64urlToBuffer(reqOptions.challenge);

const assertion = await navigator.credentials.get({ publicKey: reqOptions });

await fetch('/webauthn/authenticate', {
  method: 'POST',
  body: JSON.stringify({ challenge_id, credential: serializeCredential(assertion) }),
  headers: { 'Content-Type': 'application/json' },
});
```

---

## Configuration Reference

| Key | Description | Default |
|---|---|---|
| `authenticate_path` | POST path for assertion verification | `/webauthn/authenticate` |
| `rp_name` | Relying Party name (shown to the user) | `My App` |
| `rp_id` | Relying Party ID — must match the client origin (**required**) | — |
| `challenge_ttl` | Challenge validity in seconds | `120` |
| `credential_field` | Request body field name for the credential | `credential` |
| `challenge_id_field` | Request body field name for the challenge ID | `challenge_id` |
| `user_verification` | `required` / `preferred` / `discouraged` | `preferred` |
| `timeout` | Authenticator timeout in milliseconds | `60000` |
| `storage.type` | Challenge storage driver: `session` or `redis` | `session` |
| `storage.ttl` | Redis key TTL in seconds | same as `challenge_ttl` |

---

## Architecture

```
Guard Pipeline
├── WebAuthnAuthenticator          ← handles POST /webauthn/authenticate
│   ├── validate challenge TTL
│   ├── look up PublicKeyCredentialSource (from repository)
│   ├── AuthenticatorAssertionResponseValidator::check()
│   ├── update sign count
│   └── return Passport → AuthenticatedToken

App Controllers (implement yourself)
└── WebAuthnManager                ← injected into your controller
    ├── startRegistration()        → PublicKeyCredentialCreationOptions + store challenge
    ├── finishRegistration()       → verify attestation + save credential
    └── startAuthentication()      → PublicKeyCredentialRequestOptions + store challenge
```

---

## License

MIT
