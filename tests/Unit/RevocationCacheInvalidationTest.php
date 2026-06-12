<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Cache\Drivers\ArrayCacheDriver;
use Glueful\Extensions\Aegis\AegisPermissionProvider;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RolePermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Repositories\UserPermissionRepository;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;
use Glueful\Extensions\Aegis\Services\PermissionAssignmentService;
use Glueful\Extensions\Aegis\Services\RoleService;
use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;
use Glueful\Helpers\Utils;

/**
 * Privilege mutations through the management services must take effect on the
 * very next permission check. Before this regression suite, the services wrote
 * to the database only: AegisPermissionProvider's decision caches (check
 * results, user permissions, user roles) and UserRoleRepository's static
 * request cache were never invalidated, so a revoked role/permission stayed
 * effective until the cache TTL expired (up to 60 minutes) — and a fresh grant
 * could be masked by a cached negative for 15 minutes.
 */
final class RevocationCacheInvalidationTest extends AegisTestCase
{
    private AegisPermissionProvider $provider;

    protected function setUp(): void
    {
        parent::setUp();
        $this->provider = $this->makeProvider();
        $this->injectCache($this->provider, new ArrayCacheDriver());
    }

    public function test_role_revocation_via_role_service_takes_effect_immediately(): void
    {
        [$permissionUuid, $roleUuid] = $this->seedGrantedRole('posts.edit', 'editor');
        $userUuid = Utils::generateNanoID();

        $roleService = $this->makeRoleService();
        self::assertTrue($roleService->assignRoleToUser($userUuid, $roleUuid));

        // Warm every cache layer (decision cache, user roles, static repo cache).
        self::assertTrue($this->provider->can($userUuid, 'posts.edit', '*'));

        self::assertTrue($roleService->revokeRoleFromUser($userUuid, $roleUuid));

        self::assertFalse(
            $this->provider->can($userUuid, 'posts.edit', '*'),
            'Revoked role must not remain effective through stale caches'
        );
    }

    public function test_direct_permission_grant_and_revoke_via_assignment_service_take_effect_immediately(): void
    {
        $this->seedPermission(['slug' => 'posts.publish', 'uuid' => Utils::generateNanoID()]);
        $userUuid = Utils::generateNanoID();
        $service = $this->makeAssignmentService();

        // Cache a negative decision first — a fresh grant must not be masked by it.
        self::assertFalse($this->provider->can($userUuid, 'posts.publish', '*'));

        self::assertTrue($service->assignPermissionToUser($userUuid, 'posts.publish'));
        self::assertTrue(
            $this->provider->can($userUuid, 'posts.publish', '*'),
            'Fresh grant must not be masked by a cached negative decision'
        );

        self::assertTrue($service->revokePermissionFromUser($userUuid, 'posts.publish'));
        self::assertFalse(
            $this->provider->can($userUuid, 'posts.publish', '*'),
            'Revoked direct permission must not remain effective through stale caches'
        );
    }

    public function test_role_delete_via_role_service_takes_effect_immediately(): void
    {
        [$permissionUuid, $roleUuid] = $this->seedGrantedRole('posts.review', 'reviewer');
        $userUuid = Utils::generateNanoID();

        $roleService = $this->makeRoleService();
        self::assertTrue($roleService->assignRoleToUser($userUuid, $roleUuid));
        self::assertTrue($this->provider->can($userUuid, 'posts.review', '*'));

        self::assertTrue($roleService->deleteRole($roleUuid, true));

        self::assertFalse(
            $this->provider->can($userUuid, 'posts.review', '*'),
            'Permissions of a deleted role must not remain effective through stale caches'
        );
    }

    // ---- helpers -----------------------------------------------------------

    /** @return array{0: string, 1: string} [permissionUuid, roleUuid] */
    private function seedGrantedRole(string $permissionSlug, string $roleSlug): array
    {
        $permissionUuid = Utils::generateNanoID();
        $roleUuid = Utils::generateNanoID();
        $this->seedPermission(['slug' => $permissionSlug, 'uuid' => $permissionUuid]);
        $this->seedRole(['slug' => $roleSlug, 'uuid' => $roleUuid, 'name' => $roleSlug]);

        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO role_permissions (uuid, role_uuid, permission_uuid, created_at)
             VALUES (?,?,?,?)'
        );
        $stmt->execute([Utils::generateNanoID(), $roleUuid, $permissionUuid, date('Y-m-d H:i:s')]);

        return [$permissionUuid, $roleUuid];
    }

    private function makeRoleService(): RoleService
    {
        return new RoleService(new RoleRepository(), new UserRoleRepository(), $this->provider);
    }

    private function makeAssignmentService(): PermissionAssignmentService
    {
        return new PermissionAssignmentService(
            new PermissionRepository(),
            new UserPermissionRepository(),
            new RoleRepository(),
            new UserRoleRepository(),
            new RolePermissionRepository(),
            $this->provider
        );
    }

    /**
     * Enable the provider's distributed cache with an in-memory store.
     *
     * @param ArrayCacheDriver<mixed> $cache
     */
    private function injectCache(AegisPermissionProvider $provider, ArrayCacheDriver $cache): void
    {
        $ref = new \ReflectionClass($provider);
        foreach (['cache' => $cache, 'cacheEnabled' => true] as $prop => $value) {
            $property = $ref->getProperty($prop);
            $property->setAccessible(true);
            $property->setValue($provider, $value);
        }
    }
}
