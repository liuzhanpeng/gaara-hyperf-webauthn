<?php

declare(strict_types=1);

namespace GaaraHyperf\WebAuthn;

/**
 * Hyperf 配置提供者.
 *
 * 注册 InitListener 以自动挂载 WebAuthn 服务提供者。
 */
class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'listeners' => [
                InitListener::class,
            ],
        ];
    }
}
