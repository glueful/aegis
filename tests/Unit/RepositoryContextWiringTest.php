<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;
use Glueful\Repository\BaseRepository;

/**
 * The three pivot repositories will dispatch RBAC domain events via BaseRepository::dispatchEvent(),
 * which no-ops when its $context is null. So the repos MUST be constructed WITH the provider's
 * ApplicationContext, or those events would silently never fire.
 *
 * These tests obtain each pivot repo the production way (through AegisPermissionProvider's lazy
 * getters) and assert — via reflection on BaseRepository::$context — that it carries the provider's
 * non-null context.
 */
final class RepositoryContextWiringTest extends AegisTestCase
{
    private function repoContext(BaseRepository $repo): ?object
    {
        $prop = new \ReflectionProperty(BaseRepository::class, 'context');
        $prop->setAccessible(true);
        $value = $prop->getValue($repo);

        return is_object($value) ? $value : null;
    }

    /** @return BaseRepository */
    private function getRepo(\Glueful\Extensions\Aegis\AegisPermissionProvider $provider, string $getter): BaseRepository
    {
        $method = new \ReflectionMethod($provider, $getter);
        $method->setAccessible(true);

        return $method->invoke($provider);
    }

    private function providerContext(\Glueful\Extensions\Aegis\AegisPermissionProvider $provider): object
    {
        $prop = new \ReflectionProperty($provider, 'context');
        $prop->setAccessible(true);

        return $prop->getValue($provider);
    }

    public function test_user_role_repository_carries_provider_context(): void
    {
        $provider = $this->makeProvider();
        $repo = $this->getRepo($provider, 'getUserRoleRepository');

        self::assertNotNull($this->repoContext($repo), 'UserRoleRepository must have a non-null context so dispatched events fire');
        self::assertSame($this->providerContext($provider), $this->repoContext($repo));
    }

    public function test_user_permission_repository_carries_provider_context(): void
    {
        $provider = $this->makeProvider();
        $repo = $this->getRepo($provider, 'getUserPermissionRepository');

        self::assertNotNull($this->repoContext($repo), 'UserPermissionRepository must have a non-null context so dispatched events fire');
        self::assertSame($this->providerContext($provider), $this->repoContext($repo));
    }

    public function test_role_permission_repository_carries_provider_context(): void
    {
        $provider = $this->makeProvider();
        $repo = $this->getRepo($provider, 'getRolePermissionRepository');

        self::assertNotNull($this->repoContext($repo), 'RolePermissionRepository must have a non-null context so dispatched events fire');
        self::assertSame($this->providerContext($provider), $this->repoContext($repo));
    }
}
