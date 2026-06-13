<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;
use Glueful\Extensions\Aegis\Services\RoleService;
use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;

final class DelegatedRoleCeilingTest extends AegisTestCase
{
    public function test_actor_cannot_assign_role_they_do_not_hold_or_outrank(): void
    {
        $this->seedRoleRow('superadmin-role', 'superadmin');
        $this->seedRoleRow('editor-role', 'editor', parentUuid: 'superadmin-role', level: 1);
        $this->assignRoleDirectly('actor-user', 'editor-role');

        $service = $this->makeRoleService();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot assign a role the actor does not hold or outrank');

        $service->assignRoleToUser('actor-user', 'superadmin-role', ['assigned_by' => 'actor-user']);
    }

    public function test_actor_can_assign_descendant_role_they_outrank(): void
    {
        $this->seedRoleRow('superadmin-role', 'superadmin');
        $this->seedRoleRow('editor-role', 'editor', parentUuid: 'superadmin-role', level: 1);
        $this->assignRoleDirectly('actor-user', 'superadmin-role');

        self::assertTrue(
            $this->makeRoleService()->assignRoleToUser('target-user', 'editor-role', ['assigned_by' => 'actor-user'])
        );
    }

    public function test_actor_cannot_reparent_role_under_parent_they_do_not_hold_or_outrank(): void
    {
        $this->seedRoleRow('superadmin-role', 'superadmin');
        $this->seedRoleRow('editor-role', 'editor');
        $this->assignRoleDirectly('actor-user', 'editor-role');

        $service = $this->makeRoleService();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot set a role parent the actor does not hold or outrank');

        $service->updateRole('editor-role', ['parent_uuid' => 'superadmin-role'], 'actor-user');
    }

    public function test_actor_can_reparent_descendant_role_under_parent_they_outrank(): void
    {
        $this->seedRoleRow('superadmin-role', 'superadmin');
        $this->seedRoleRow('editor-role', 'editor');
        $this->assignRoleDirectly('actor-user', 'superadmin-role');

        self::assertTrue(
            $this->makeRoleService()->updateRole(
                'editor-role',
                ['parent_uuid' => 'superadmin-role'],
                'actor-user'
            )
        );
    }

    private function makeRoleService(): RoleService
    {
        return new RoleService(new RoleRepository(), new UserRoleRepository());
    }

    private function seedRoleRow(
        string $uuid,
        string $slug,
        ?string $parentUuid = null,
        int $level = 0
    ): void {
        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO roles (uuid, name, slug, parent_uuid, level, is_system, status)
             VALUES (?, ?, ?, ?, ?, 0, "active")'
        );
        $stmt->execute([$uuid, $slug, $slug, $parentUuid, $level]);
    }

    private function assignRoleDirectly(string $userUuid, string $roleUuid): void
    {
        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO user_roles (uuid, user_uuid, role_uuid, scope, granted_by, expires_at, created_at)
             VALUES (?, ?, ?, NULL, NULL, NULL, datetime("now"))'
        );
        $stmt->execute([uniqid('ur_', true), $userUuid, $roleUuid]);
    }
}
