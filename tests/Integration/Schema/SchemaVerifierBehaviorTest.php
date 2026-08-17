<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Integration\Schema;

use Glueful\Database\Connection;
use Glueful\Database\Migrations\MigrationManager;
use Glueful\Extensions\Aegis\Schema\AegisSchemaVerifier;
use Glueful\Services\FileFinder;
use PHPUnit\Framework\TestCase;

/**
 * The adoption contract (schema policy spec B7): each migration's verifier proof must be FALSE
 * on a deliberately incomplete predecessor fixture and TRUE only after that exact migration's
 * up() ran. For the seed migration this pins that table existence alone can never certify it.
 */
final class SchemaVerifierBehaviorTest extends TestCase
{
    private Connection $connection;
    private MigrationManager $manager;
    private AegisSchemaVerifier $verifier;
    private string $dbPath;

    protected function setUp(): void
    {
        $this->dbPath = sys_get_temp_dir() . '/aegis-verify-' . uniqid('', true) . '.sqlite';
        // 003_SeedDefaultRoles constructs its own `new Connection()` inside up() instead of
        // using the injected schema builder's connection (latent shipped-file bug; editing it
        // would drift its checksum and mark every existing install divergent). Pin the DEFAULT
        // connection env to the fixture db so the seed lands where the migration ran.
        putenv('DB_DRIVER=sqlite');
        putenv('DB_SQLITE_DATABASE=' . $this->dbPath);
        $_ENV['DB_DRIVER'] = 'sqlite';
        $_ENV['DB_SQLITE_DATABASE'] = $this->dbPath;
        $this->connection = new Connection([
            'engine' => 'sqlite',
            'sqlite' => ['primary' => $this->dbPath],
            'pooling' => ['enabled' => false],
        ]);
        $this->manager = new MigrationManager(
            dirname(__DIR__, 3) . '/migrations',
            new FileFinder(),
            null,
            $this->connection
        );
        $this->verifier = new AegisSchemaVerifier();
    }

    protected function tearDown(): void
    {
        putenv('DB_DRIVER');
        putenv('DB_SQLITE_DATABASE');
        unset($_ENV['DB_DRIVER'], $_ENV['DB_SQLITE_DATABASE']);
        @unlink($this->dbPath);
    }

    private function runMigration(string $basename): void
    {
        $result = $this->manager->migrate(dirname(__DIR__, 3) . '/migrations/' . $basename);
        self::assertSame([], $result['failed'], "fixture migration {$basename} must apply");
    }

    public function testRolesTablesProofFlipsWithItsMigration(): void
    {
        self::assertFalse($this->verifier->verify($this->connection, '001_CreateRolesTables.php'));
        $this->runMigration('001_CreateRolesTables.php');
        self::assertTrue($this->verifier->verify($this->connection, '001_CreateRolesTables.php'));
    }

    public function testPermissionsTablesProofRequiresItsOwnMigrationNotJustThePredecessor(): void
    {
        $this->runMigration('001_CreateRolesTables.php');
        self::assertFalse($this->verifier->verify($this->connection, '002_CreatePermissionsTables.php'));
        $this->runMigration('002_CreatePermissionsTables.php');
        self::assertTrue($this->verifier->verify($this->connection, '002_CreatePermissionsTables.php'));
    }

    public function testSeedProofIsFalseWhileAllTablesExistButUnseeded(): void
    {
        $this->runMigration('001_CreateRolesTables.php');
        $this->runMigration('002_CreatePermissionsTables.php');
        // Every table exists; the seed has not run. Table existence MUST NOT certify the seed.
        self::assertFalse($this->verifier->verify($this->connection, '003_SeedDefaultRoles.php'));
        $this->runMigration('003_SeedDefaultRoles.php');
        self::assertTrue($this->verifier->verify($this->connection, '003_SeedDefaultRoles.php'));
    }

    public function testSeedProofSurvivesExtraHostManagedRows(): void
    {
        $this->runMigration('001_CreateRolesTables.php');
        $this->runMigration('002_CreatePermissionsTables.php');
        $this->runMigration('003_SeedDefaultRoles.php');
        $this->connection->getPDO()->exec(
            "INSERT INTO roles (uuid, name, slug, status, level) VALUES ('hostrole12ab', 'Host', 'host', 'active', 5)"
        );
        self::assertTrue($this->verifier->verify($this->connection, '003_SeedDefaultRoles.php'));
    }

    public function testUnknownBasenameIsNeverAdoptable(): void
    {
        self::assertFalse($this->verifier->verify($this->connection, '999_Unknown.php'));
    }
}
