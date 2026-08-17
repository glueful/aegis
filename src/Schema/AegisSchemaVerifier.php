<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Schema;

use Glueful\Database\Connection;
use Glueful\Extensions\Schema\StructuralVerifierInterface;

/**
 * Structural verifier for glueful/aegis (schema policy spec B7): each migration's receipt may be
 * adopted only when THAT migration's observable effect is present — created tables for 001/002,
 * the seeded RBAC catalog for 003. A table's mere existence never certifies the seed. Extra
 * host-managed rows do not invalidate any proof; unknown basenames are never adoptable.
 */
final class AegisSchemaVerifier implements StructuralVerifierInterface
{
    private const SEEDED_ROLES = ['superuser', 'administrator', 'user'];

    private const SEEDED_PERMISSIONS = [
        'system.access', 'system.config',
        'users.view', 'users.create', 'users.edit', 'users.delete',
        'roles.view', 'roles.create', 'roles.edit', 'roles.delete', 'roles.assign',
        'content.view', 'content.create', 'content.edit', 'content.delete',
    ];

    private const SEEDED_ASSIGNMENT_COUNT = 30; // 15 superuser + 14 administrator + 1 user

    public function source(): string
    {
        return 'glueful/aegis';
    }

    /** @return list<string> */
    public function migrationBasenames(): array
    {
        return [
            '001_CreateRolesTables.php',
            '002_CreatePermissionsTables.php',
            '003_SeedDefaultRoles.php',
        ];
    }

    public function verify(Connection $db, string $migrationBasename): bool
    {
        return match ($migrationBasename) {
            '001_CreateRolesTables.php' => $this->tablesWithColumns($db, [
                'roles' => ['uuid', 'name', 'slug', 'parent_uuid', 'status', 'level'],
                'user_roles' => ['uuid', 'user_uuid', 'role_uuid', 'granted_by'],
            ]),
            '002_CreatePermissionsTables.php' => $this->tablesWithColumns($db, [
                'permissions' => ['uuid', 'slug'],
                'role_permissions' => ['role_uuid', 'permission_uuid'],
                'user_permissions' => ['user_uuid', 'permission_uuid'],
                'permission_audit' => ['uuid'],
            ]),
            '003_SeedDefaultRoles.php' => $this->seededCatalogPresent($db),
            default => false,
        };
    }

    /** @param array<string, list<string>> $expectations table => required columns */
    private function tablesWithColumns(Connection $db, array $expectations): bool
    {
        $schema = $db->getSchemaBuilder();
        foreach ($expectations as $table => $columns) {
            if (!$schema->hasTable($table)) {
                return false;
            }
            foreach ($columns as $column) {
                if (!$schema->hasColumn($table, $column)) {
                    return false;
                }
            }
        }
        return true;
    }

    private function seededCatalogPresent(Connection $db): bool
    {
        $schema = $db->getSchemaBuilder();
        foreach (['roles', 'permissions', 'role_permissions'] as $table) {
            if (!$schema->hasTable($table)) {
                return false;
            }
        }

        $roleRows = $db->table('roles')
            ->select(['slug'])
            ->whereIn('slug', self::SEEDED_ROLES)
            ->where('status', 'active')
            ->get();
        if (count(array_unique(array_column($roleRows, 'slug'))) !== count(self::SEEDED_ROLES)) {
            return false;
        }

        $permissionRows = $db->table('permissions')
            ->select(['slug'])
            ->whereIn('slug', self::SEEDED_PERMISSIONS)
            ->get();
        if (count(array_unique(array_column($permissionRows, 'slug'))) !== count(self::SEEDED_PERMISSIONS)) {
            return false;
        }

        // Count DISTINCT seeded role→permission assignments via the uuid join. Host-managed
        // extras are fine; fewer than the 30 migration-defined pairs is not.
        $sql = 'SELECT COUNT(*) FROM (SELECT DISTINCT rp.role_uuid, rp.permission_uuid '
            . 'FROM role_permissions rp '
            . 'JOIN roles r ON r.uuid = rp.role_uuid '
            . 'JOIN permissions p ON p.uuid = rp.permission_uuid '
            . 'WHERE r.slug IN (' . $this->placeholders(self::SEEDED_ROLES) . ') '
            . 'AND p.slug IN (' . $this->placeholders(self::SEEDED_PERMISSIONS) . ')) pairs';
        $stmt = $db->getPDO()->prepare($sql);
        $stmt->execute([...self::SEEDED_ROLES, ...self::SEEDED_PERMISSIONS]);
        return (int) $stmt->fetchColumn() >= self::SEEDED_ASSIGNMENT_COUNT;
    }

    /** @param list<string> $values */
    private function placeholders(array $values): string
    {
        return implode(',', array_fill(0, count($values), '?'));
    }
}
