<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\AegisPermissionProvider;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RolePermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Repositories\UserPermissionRepository;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;
use Glueful\Extensions\Aegis\Services\PermissionAssignmentService;
use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;
use Glueful\Helpers\Utils;

/**
 * PermissionAssignmentService used to run its own direct/role/hierarchy walk —
 * a second authorization engine that could disagree with the runtime one
 * (AegisPermissionProvider::can()). userHasPermission() now delegates to the
 * provider, so the management API's dry-run check answers exactly what
 * enforcement would answer. These tests pin the agreement in scenarios where
 * the two engines historically could diverge.
 */
final class PermissionCheckConsolidationTest extends AegisTestCase
{
    public function test_management_check_agrees_with_runtime_engine(): void
    {
        $this->seedPermission(['uuid' => 'perm-direct', 'slug' => 'posts.publish']);
        $this->seedGrantedRole('entries.edit', 'editor', 'perm-role', 'editor-role');
        $this->assignRoleDirectly('user-1', 'editor-role', ['tenant_id' => 'tenant_1']);
        $this->grantDirectly('user-1', 'perm-direct');

        $provider = $this->makeInitializedProvider();
        $service = $this->makeAssignmentService($provider);

        $cases = [
            ['posts.publish', '*', []],                                          // direct grant
            ['entries.edit', '*', ['scope' => ['tenant_id' => 'tenant_1']]],     // scoped role grant
            ['entries.edit', '*', ['scope' => ['tenant_id' => 'tenant_2']]],     // wrong tenant
            ['entries.edit', '*', []],                                           // unscoped check
            ['no.such.permission', '*', []],                                     // unknown slug
        ];

        foreach ($cases as [$permission, $resource, $context]) {
            self::assertSame(
                $provider->can('user-1', $permission, $resource, $context),
                $service->userHasPermission('user-1', $permission, $resource, $context),
                "Check endpoint must answer what enforcement answers for '{$permission}'"
            );
        }
    }

    public function test_hierarchy_config_cannot_split_the_two_paths(): void
    {
        // Permission granted to a parent role; user holds only the child. The old
        // service engine always walked the hierarchy, while the provider honors
        // enable_hierarchy/enable_inheritance — with hierarchy disabled the two
        // engines disagreed. Delegation makes a disagreement impossible.
        $this->seedGrantedRole('reports.view', 'manager', 'perm-h', 'manager-role');
        $this->seedChildRole('analyst', 'analyst-role', 'manager-role');
        $this->assignRoleDirectly('user-2', 'analyst-role');

        $provider = $this->makeInitializedProvider(['enable_hierarchy' => false]);
        $service = $this->makeAssignmentService($provider);

        self::assertFalse($provider->can('user-2', 'reports.view', '*'));
        self::assertFalse(
            $service->userHasPermission('user-2', 'reports.view', '*'),
            'With hierarchy disabled, the management check must deny exactly like the runtime engine'
        );
    }

    // ---- helpers -----------------------------------------------------------

    /** @param array<string, mixed> $config */
    private function makeInitializedProvider(array $config = []): AegisPermissionProvider
    {
        $provider = $this->makeProvider();
        $provider->initialize(array_merge(['cache_enabled' => false], $config));

        return $provider;
    }

    private function makeAssignmentService(AegisPermissionProvider $provider): PermissionAssignmentService
    {
        return new PermissionAssignmentService(
            new PermissionRepository(),
            new UserPermissionRepository(),
            new RoleRepository(),
            new UserRoleRepository(),
            new RolePermissionRepository(),
            $provider
        );
    }

    private function seedGrantedRole(
        string $permissionSlug,
        string $roleSlug,
        string $permissionUuid,
        string $roleUuid
    ): void {
        $this->seedPermission(['uuid' => $permissionUuid, 'slug' => $permissionSlug]);
        $this->seedRole(['uuid' => $roleUuid, 'slug' => $roleSlug]);

        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO role_permissions (uuid, role_uuid, permission_uuid, created_at)
             VALUES (?, ?, ?, datetime("now"))'
        );
        $stmt->execute([Utils::generateNanoID(), $roleUuid, $permissionUuid]);
    }

    private function seedChildRole(string $slug, string $uuid, string $parentUuid): void
    {
        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO roles (uuid, name, slug, parent_uuid, level, is_system, status)
             VALUES (?, ?, ?, ?, 1, 0, "active")'
        );
        $stmt->execute([$uuid, $slug, $slug, $parentUuid]);
    }

    /** @param array<string, mixed> $scope */
    private function assignRoleDirectly(string $userUuid, string $roleUuid, array $scope = []): void
    {
        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO user_roles (uuid, user_uuid, role_uuid, scope, granted_by, expires_at, created_at)
             VALUES (?, ?, ?, ?, NULL, NULL, datetime("now"))'
        );
        $stmt->execute([
            Utils::generateNanoID(),
            $userUuid,
            $roleUuid,
            $scope === [] ? null : json_encode($scope),
        ]);
    }

    private function grantDirectly(string $userUuid, string $permissionUuid): void
    {
        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO user_permissions (uuid, user_uuid, permission_uuid, created_at)
             VALUES (?, ?, ?, datetime("now"))'
        );
        $stmt->execute([Utils::generateNanoID(), $userUuid, $permissionUuid]);
    }
}
