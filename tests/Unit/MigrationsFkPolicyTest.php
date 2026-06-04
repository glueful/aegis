<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Database\Connection;
use PHPUnit\Framework\TestCase;

/**
 * Guards the §2 referential-integrity policy: Aegis actor columns (user_uuid / granted_by) are
 * indexed UUIDs with NO cross-package FK into `users`, while intra-package FKs (role/permission)
 * are retained. Applies the real migration up() methods to a fresh SQLite db and inspects
 * PRAGMA foreign_key_list.
 */
final class MigrationsFkPolicyTest extends TestCase
{
    private Connection $connection;
    private string $dbPath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dbPath = sys_get_temp_dir() . '/aegis-fk-' . uniqid('', true) . '.sqlite';
        $this->connection = new Connection([
            'engine' => 'sqlite',
            'sqlite' => ['primary' => $this->dbPath],
            'pooling' => ['enabled' => false],
        ]);

        $migrations = dirname(__DIR__, 2) . '/migrations';
        require_once $migrations . '/001_CreateRolesTables.php';
        require_once $migrations . '/002_CreatePermissionsTables.php';

        $schema = $this->connection->getSchemaBuilder();
        // Migration files live in migrations/ (not PSR-4 src/), so they are require_once'd above
        // and instantiated by FQCN — phpstan cannot see them statically.
        $rolesClass = 'Glueful\\Extensions\\Aegis\\Database\\Migrations\\CreateRolesTables';
        $permsClass = 'Glueful\\Extensions\\Aegis\\Database\\Migrations\\CreatePermissionsTables';
        /** @phpstan-ignore-next-line migration classes are require_once'd from migrations/, not PSR-4 */
        (new $rolesClass())->up($schema);
        /** @phpstan-ignore-next-line migration classes are require_once'd from migrations/, not PSR-4 */
        (new $permsClass())->up($schema);
    }

    protected function tearDown(): void
    {
        if (isset($this->dbPath) && is_file($this->dbPath)) {
            @unlink($this->dbPath);
        }
        parent::tearDown();
    }

    /** @return list<string> referenced table names from PRAGMA foreign_key_list($table) */
    private function fkTargets(string $table): array
    {
        $stmt = $this->connection->getPDO()->query("PRAGMA foreign_key_list('" . $table . "')");
        $rows = $stmt === false ? [] : $stmt->fetchAll(\PDO::FETCH_ASSOC);
        return array_values(array_map(static fn($r) => (string) $r['table'], $rows));
    }

    public function test_actor_columns_have_no_fk_into_users(): void
    {
        foreach (['user_roles', 'user_permissions', 'role_permissions'] as $table) {
            self::assertNotContains(
                'users',
                $this->fkTargets($table),
                "$table must not have a cross-package FK into users (§2)"
            );
        }
    }

    public function test_intra_package_fks_are_retained(): void
    {
        self::assertContains('roles', $this->fkTargets('user_roles'), 'user_roles.role_uuid -> roles');
        self::assertContains('permissions', $this->fkTargets('role_permissions'), 'role_permissions.permission_uuid');
        self::assertContains('permissions', $this->fkTargets('user_permissions'), 'user_permissions.permission_uuid');
    }
}
