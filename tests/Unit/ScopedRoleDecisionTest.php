<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\AegisPermissionProvider;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;
use Glueful\Extensions\Aegis\Services\RoleService;
use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;
use Glueful\Helpers\Utils;

final class ScopedRoleDecisionTest extends AegisTestCase
{
    public function test_has_role_respects_assignment_scope(): void
    {
        $this->seedRole(['uuid' => 'editor-role', 'slug' => 'editor']);
        $this->assignRoleDirectly('user-1', 'editor-role', ['tenant_id' => 'tenant_1']);

        $provider = $this->makeInitializedProvider();

        self::assertTrue($provider->hasRole('user-1', 'editor', ['tenant_id' => 'tenant_1']));
        self::assertFalse($provider->hasRole('user-1', 'editor', ['tenant_id' => 'tenant_2']));
    }

    public function test_can_uses_scope_when_evaluating_role_permissions(): void
    {
        $this->seedGrantedRole('entries.edit', 'editor', 'permission-1', 'editor-role');
        $this->assignRoleDirectly('user-1', 'editor-role', ['tenant_id' => 'tenant_1']);

        $provider = $this->makeInitializedProvider();

        self::assertTrue(
            $provider->can('user-1', 'entries.edit', '*', ['scope' => ['tenant_id' => 'tenant_1']])
        );
        self::assertFalse(
            $provider->can('user-1', 'entries.edit', '*', ['scope' => ['tenant_id' => 'tenant_2']])
        );
    }

    public function test_same_role_can_be_assigned_under_different_scopes(): void
    {
        $this->seedRole(['uuid' => 'editor-role', 'slug' => 'editor']);
        $service = new RoleService(new RoleRepository(), new UserRoleRepository());

        self::assertTrue(
            $service->assignRoleToUser('user-1', 'editor-role', ['scope' => ['tenant_id' => 'tenant_1']])
        );
        self::assertTrue(
            $service->assignRoleToUser('user-1', 'editor-role', ['scope' => ['tenant_id' => 'tenant_2']])
        );

        $stmt = $this->connection->getPDO()->prepare(
            'SELECT scope FROM user_roles WHERE user_uuid = ? AND role_uuid = ? ORDER BY scope'
        );
        $stmt->execute(['user-1', 'editor-role']);
        $scopes = array_map(static fn(array $row): array => json_decode((string) $row['scope'], true), $stmt->fetchAll());

        self::assertCount(2, $scopes);
        self::assertContains(['tenant_id' => 'tenant_1'], $scopes);
        self::assertContains(['tenant_id' => 'tenant_2'], $scopes);
    }

    private function makeInitializedProvider(): AegisPermissionProvider
    {
        $provider = $this->makeProvider();
        $provider->initialize(['cache_enabled' => false]);

        return $provider;
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

    /**
     * @param array<string, mixed> $scope
     */
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
}
