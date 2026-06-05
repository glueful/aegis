<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Support;

use Glueful\Bootstrap\ApplicationContext;
use Glueful\Database\Connection;
use Glueful\Extensions\Aegis\AegisPermissionProvider;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Helpers\Utils;
use PHPUnit\Framework\TestCase;

/**
 * Lightweight SQLite harness for Aegis catalog tests.
 *
 * BaseRepository shares a single static Connection across all repositories, so injecting one
 * here (via any repo constructor) makes every `new XRepository()` use the in-test SQLite db.
 */
abstract class AegisTestCase extends TestCase
{
    protected Connection $connection;
    private string $dbPath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->dbPath = sys_get_temp_dir() . '/aegis-' . uniqid('', true) . '.sqlite';
        $this->connection = new Connection([
            'engine' => 'sqlite',
            'sqlite' => ['primary' => $this->dbPath],
            'pooling' => ['enabled' => false],
        ]);
        $this->createSchema();
        // Register as the shared repository connection (BaseRepository::$sharedConnection).
        new PermissionRepository($this->connection);
        // Static lookup cache persists across cases (distinct DBs) — clear for isolation.
        PermissionRepository::clearCache();
    }

    protected function tearDown(): void
    {
        if (isset($this->dbPath) && is_file($this->dbPath)) {
            @unlink($this->dbPath);
        }
        parent::tearDown();
    }

    private function createSchema(): void
    {
        $pdo = $this->connection->getPDO();
        $pdo->exec('CREATE TABLE permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT, name TEXT, slug TEXT, description TEXT, category TEXT,
            resource_type TEXT, is_system INTEGER DEFAULT 0, managed_by TEXT,
            metadata TEXT, created_at TEXT, deleted_at TEXT
        )');
        $pdo->exec('CREATE TABLE roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT, name TEXT, slug TEXT, description TEXT, parent_uuid TEXT,
            level INTEGER DEFAULT 0, is_system INTEGER DEFAULT 0, managed_by TEXT,
            metadata TEXT, status TEXT DEFAULT "active",
            created_at TEXT, updated_at TEXT, deleted_at TEXT
        )');
        $pdo->exec('CREATE TABLE role_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT, role_uuid TEXT, permission_uuid TEXT, resource_filter TEXT,
            constraints TEXT, granted_by TEXT, expires_at TEXT,
            created_at TEXT, updated_at TEXT, deleted_at TEXT
        )');
    }

    protected function makeProvider(): AegisPermissionProvider
    {
        return new AegisPermissionProvider(ApplicationContext::forTesting(sys_get_temp_dir()));
    }

    /** @param array<string,mixed> $row */
    protected function seedPermission(array $row): void
    {
        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO permissions (uuid, name, slug, managed_by, is_system) VALUES (?,?,?,?,0)'
        );
        $stmt->execute([
            $row['uuid'] ?? Utils::generateNanoID(),
            $row['name'] ?? $row['slug'],
            $row['slug'],
            $row['managed_by'] ?? null,
        ]);
    }

    protected function permissionExists(string $slug): bool
    {
        // "Exists" = active (not soft-deleted), matching how the app sees the catalog.
        $stmt = $this->connection->getPDO()->prepare(
            'SELECT COUNT(*) FROM permissions WHERE slug = ? AND deleted_at IS NULL'
        );
        $stmt->execute([$slug]);
        return (int) $stmt->fetchColumn() > 0;
    }

    /** @param array<string,mixed> $row */
    protected function seedRole(array $row): void
    {
        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO roles (uuid, name, slug, managed_by, level, is_system, status)
             VALUES (?,?,?,?,0,0,?)'
        );
        $stmt->execute([
            $row['uuid'] ?? Utils::generateNanoID(),
            $row['name'] ?? $row['slug'],
            $row['slug'],
            $row['managed_by'] ?? null,
            'active',
        ]);
    }

    protected function roleExists(string $slug): bool
    {
        $stmt = $this->connection->getPDO()->prepare(
            'SELECT COUNT(*) FROM roles WHERE slug = ? AND deleted_at IS NULL'
        );
        $stmt->execute([$slug]);
        return (int) $stmt->fetchColumn() > 0;
    }

    /** @return string[] */
    protected function roleGrantSlugs(string $roleSlug): array
    {
        $stmt = $this->connection->getPDO()->prepare(
            'SELECT p.slug FROM role_permissions rp
             JOIN roles r ON r.uuid = rp.role_uuid
             JOIN permissions p ON p.uuid = rp.permission_uuid
             WHERE r.slug = ? AND rp.deleted_at IS NULL'
        );
        $stmt->execute([$roleSlug]);
        return array_map(static fn($r) => (string) $r['slug'], $stmt->fetchAll(\PDO::FETCH_ASSOC));
    }
}
