# gaara-hyperf-webauthn

[English](README.en.md)

---

基于 [gaara-hyperf](https://github.com/lzpeng/gaara-hyperf) 的 WebAuthn（FIDO2 Passkey）认证器扩展。

### 功能

- 完整的 WebAuthn 注册和登录流程
- 支持 Passkey（discoverable credential）无用户名登录
- 挑战存储：Session（Web 场景）/ Redis（API 场景）
- 遵循 gaara-hyperf 扩展模式，开箱即用
- 兼容 `web-auth/webauthn-lib ^4.8`（Spomky-Labs 官方库）

### 安装

```bash
composer require lzpeng/gaara-hyperf-webauthn
```

### 快速上手

#### 1. 实现用户模型

```php
use GaaraHyperf\WebAuthn\WebAuthnUserInterface;

class User implements WebAuthnUserInterface
{
    public function getIdentifier(): string
    {
        return (string) $this->id; // 用作 WebAuthn user handle，建议使用不可变 ID（如 UUID/数字）
    }

    public function getWebAuthnDisplayName(): string
    {
        return $this->name; // 仅用于认证器 UI 展示，不影响安全性
    }
}
```

#### 2. 实现凭据仓库

```php
use GaaraHyperf\WebAuthn\Credential\PublicKeyCredentialRepositoryInterface;
use Webauthn\PublicKeyCredentialSource;

class CredentialRepository implements PublicKeyCredentialRepositoryInterface
{
    public function findByCredentialId(string $credentialId): ?PublicKeyCredentialSource
    {
        // 按二进制 credentialId 查询数据库
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

> **提示**：凭据数据库表建议至少包含 `credential_id`（唯一索引）、`user_identifier`（索引）、`data`（JSON 列）、`updated_at` 字段。

#### 3. 绑定依赖

在应用的 `ConfigProvider` 或 `AppServiceProvider` 中：

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

#### 4. 配置认证器

在 `publish/auth.php` 的 Guard 配置中：

```php
'guards' => [
    'web' => [
        'user_provider' => [...],
        'authenticators' => [
            'webauthn' => [
                'authenticate_path'   => '/webauthn/authenticate', // POST 断言验证端点
                'rp_name'             => 'My App',
                'rp_id'               => 'example.com',           // 必须与前端域名匹配
                'challenge_ttl'       => 120,                      // 挑战有效期（秒）
                'credential_field'    => 'credential',             // 请求体字段名
                'challenge_id_field'  => 'challenge_id',
                'user_verification'   => 'preferred',              // required | preferred | discouraged
                'timeout'             => 60000,                    // 毫秒
                'storage'             => ['type' => 'session'],    // 或 ['type' => 'redis', 'ttl' => 300]
            ],
        ],
    ],
],
```

#### 5. 实现注册 Controller

注册流程（生成 options + 验证响应）通过 `WebAuthnManager` 服务完成，由应用自行实现 Controller：

```php
use GaaraHyperf\WebAuthn\Service\WebAuthnManager;
use GaaraHyperf\WebAuthn\WebAuthnUserInterface;

class WebAuthnController
{
    public function __construct(
        private WebAuthnManager $manager,
    ) {}

    // 步骤 1: 生成注册 Options（前端调用 navigator.credentials.create() 前请求）
    #[PostMapping('/webauthn/register/options')]
    public function registrationOptions(): array
    {
        /** @var WebAuthnUserInterface $user */
        $user = auth('web')->user();
        return $this->manager->startRegistration($user);
        // 返回: {'challenge_id': '...', 'options': {...PublicKeyCredentialCreationOptions...}}
    }

    // 步骤 2: 完成注册（前端将 navigator.credentials.create() 结果提交）
    #[PostMapping('/webauthn/register/verify')]
    public function registrationVerify(RequestInterface $request): array
    {
        $body = $request->getParsedBody();
        $user = auth('web')->user();
        $source = $this->manager->finishRegistration(
            challengeId:    $body['challenge_id'],
            credentialData: $body['credential'],
            host:           $request->getUri()->getHost(),
        );
        return ['status' => 'ok', 'credential_id' => base64_encode($source->publicKeyCredentialId)];
    }

    // 步骤 3: 生成登录 Options（前端调用 navigator.credentials.get() 前请求）
    #[PostMapping('/webauthn/login/options')]
    public function loginOptions(RequestInterface $request): array
    {
        $body = $request->getParsedBody();
        // 已知用户流程传 user_identifier；Passkey 流程传 null
        return $this->manager->startAuthentication($body['user_identifier'] ?? null);
        // 返回: {'challenge_id': '...', 'options': {...PublicKeyCredentialRequestOptions...}}
    }

    // 步骤 4: 断言验证（由 Guard 的 WebAuthnAuthenticator 处理，无需手动实现）
    // POST /webauthn/authenticate  ← authenticate_path 配置项
    // 请求体: {'challenge_id': '...', 'credential': {...navigator.credentials.get() 结果...}}
}
```

#### 6. 前端集成示例

```javascript
// 注册
const optionsResp = await fetch('/webauthn/register/options', { method: 'POST' });
const { challenge_id, options } = await optionsResp.json();

// 将 base64url 字符串转为 ArrayBuffer（需要辅助函数）
options.challenge = base64urlToBuffer(options.challenge);
options.user.id   = base64urlToBuffer(options.user.id);

const credential = await navigator.credentials.create({ publicKey: options });

await fetch('/webauthn/register/verify', {
  method: 'POST',
  body: JSON.stringify({ challenge_id, credential: serializeCredential(credential) }),
  headers: { 'Content-Type': 'application/json' },
});

// 登录
const loginResp = await fetch('/webauthn/login/options', {
  method: 'POST',
  body: JSON.stringify({ user_identifier: userId }),  // Passkey 流程传 null
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

### 配置参考

| 配置项 | 说明 | 默认值 |
|---|---|---|
| `authenticate_path` | 断言验证 POST 路径 | `/webauthn/authenticate` |
| `rp_name` | Relying Party 名称（展示给用户） | `My App` |
| `rp_id` | Relying Party ID（必须与域名匹配，**必填**） | — |
| `challenge_ttl` | 挑战有效期（秒） | `120` |
| `credential_field` | 请求体中 credential 字段名 | `credential` |
| `challenge_id_field` | 请求体中 challenge_id 字段名 | `challenge_id` |
| `user_verification` | 用户验证要求：`required` / `preferred` / `discouraged` | `preferred` |
| `timeout` | 认证器超时（毫秒） | `60000` |
| `storage.type` | 挑战存储驱动：`session` / `redis` | `session` |
| `storage.ttl` | Redis 存储的 key 过期时间（秒） | 与 `challenge_ttl` 相同 |

### 架构说明

```
Guard Pipeline
├── WebAuthnAuthenticator          ← 处理 POST /webauthn/authenticate
│   ├── 验证 challenge TTL
│   ├── 查找 PublicKeyCredentialSource（从仓库）
│   ├── AuthenticatorAssertionResponseValidator::check()
│   ├── 更新 sign count
│   └── 返回 Passport → AuthenticatedToken

App Controllers (自行实现)
└── WebAuthnManager                ← 注入到 Controller
    ├── startRegistration()        → PublicKeyCredentialCreationOptions + 存挑战
    ├── finishRegistration()       → 验证 attestation + 存凭据
    └── startAuthentication()      → PublicKeyCredentialRequestOptions + 存挑战
```

---

## 许可

MIT
