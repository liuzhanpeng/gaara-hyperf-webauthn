<?php

declare(strict_types=1);

namespace GaaraHyperf\WebAuthn\ChallengeStorage;

use Hyperf\Contract\ContainerInterface;
use Hyperf\Contract\SessionInterface;
use Hyperf\Redis\Redis;
use InvalidArgumentException;

/**
 * WebAuthn 挑战存储工厂.
 *
 * 根据配置中的 `type` 字段（session / redis）实例化对应的存储驱动。
 */
class ChallengeStorageFactory
{
    public function __construct(
        private ContainerInterface $container,
    ) {
    }

    /**
     * @param array $config 存储配置，格式：['type' => 'session'] 或 ['type' => 'redis', 'ttl' => 300]
     */
    public function create(array $config, int $challengeTtl = 300): ChallengeStorageInterface
    {
        $type = $config['type'] ?? 'session';

        return match ($type) {
            'session' => new SessionChallengeStorage(
                $this->container->get(SessionInterface::class)
            ),
            'redis' => new RedisChallengeStorage(
                $this->container->get(Redis::class),
                $config['ttl'] ?? $challengeTtl,
            ),
            default => throw new InvalidArgumentException(
                sprintf('Unsupported WebAuthn challenge storage type: "%s". Supported types: session, redis.', $type)
            ),
        };
    }
}
