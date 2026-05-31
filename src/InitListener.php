<?php

declare(strict_types=1);

namespace GaaraHyperf\WebAuthn;

use GaaraHyperf\ServiceProvider\ServiceProviderRegisterEvent;
use Hyperf\Event\Contract\ListenerInterface;

/**
 * 初始化监听器.
 *
 * 监听 ServiceProviderRegisterEvent，将 WebAuthn ServiceProvider 注册到服务注册表中。
 */
class InitListener implements ListenerInterface
{
    public function listen(): array
    {
        return [
            ServiceProviderRegisterEvent::class,
        ];
    }

    /**
     * @param ServiceProviderRegisterEvent $event
     */
    public function process(object $event): void
    {
        $event->serviceProviderRegistry()->register(new ServiceProvider());
    }
}
