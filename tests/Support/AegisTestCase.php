<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Support;

use Glueful\Bootstrap\ApplicationContext;
use Glueful\Database\Connection;
use Glueful\Events\Contracts\BaseEvent;
use Glueful\Events\EventDispatcher;
use Glueful\Events\EventService;
use Glueful\Events\ListenerProvider;
use Glueful\Extensions\Aegis\AegisPermissionProvider;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Helpers\Utils;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

/**
 * Lightweight SQLite harness for Aegis catalog tests.
 *
 * BaseRepository shares a single static Connection across all repositories, so injecting one
 * here (via any repo constructor) makes every `new XRepository()` use the in-test SQLite db.
 */
abstract class AegisTestCase extends TestCase
{
    protected Connection $connection;
    protected ApplicationContext $context;
    private string $dbPath;

    /**
     * Domain events captured during a test. The pivot repos dispatch via
     * BaseRepository::dispatchEvent() -> app($context, EventService::class)->dispatch(),
     * so we put a real EventService (with a catch-all BaseEvent listener) behind a minimal
     * container on $this->context. Without this container, getContainer() throws and
     * dispatchEvent() swallows it — events would silently never fire.
     *
     * @var list<BaseEvent>
     */
    protected array $recordedEvents = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->dbPath = sys_get_temp_dir() . '/aegis-' . uniqid('', true) . '.sqlite';
        // Build the test context first and bind it to the SQLite connection. BaseRepository's
        // shared connection is only replaced when a context arrives and the current shared
        // connection hasContext() === false; binding it here keeps repos constructed WITH this
        // context (production wiring) from swapping our in-test SQLite db for a default one.
        $this->context = ApplicationContext::forTesting(sys_get_temp_dir());
        $this->installEventCapture();
        $this->connection = new Connection([
            'engine' => 'sqlite',
            'sqlite' => ['primary' => $this->dbPath],
            'pooling' => ['enabled' => false],
        ], $this->context);
        $this->createSchema();
        // Register as the shared repository connection (BaseRepository::$sharedConnection).
        new PermissionRepository($this->connection);
        // Static lookup caches persist across cases (distinct DBs) — clear for isolation.
        PermissionRepository::clearCache();
        RoleRepository::clearCache();
        \Glueful\Extensions\Aegis\Repositories\UserRoleRepository::flushGlobalCache();
        \Glueful\Extensions\Aegis\Repositories\UserPermissionRepository::flushGlobalCache();
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
        $pdo->exec('CREATE TABLE user_roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT, user_uuid TEXT, role_uuid TEXT, scope TEXT,
            granted_by TEXT, expires_at TEXT, created_at TEXT
        )');
        $pdo->exec('CREATE TABLE user_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT, user_uuid TEXT, permission_uuid TEXT, resource_filter TEXT,
            constraints TEXT, granted_by TEXT, expires_at TEXT, created_at TEXT
        )');
    }

    protected function makeProvider(): AegisPermissionProvider
    {
        return new AegisPermissionProvider($this->context);
    }

    /**
     * Build a real EventService whose dispatcher records every BaseEvent into
     * $this->recordedEvents, and expose it through a minimal PSR-11 container set on the
     * test context so app($context, EventService::class) returns exactly this instance.
     */
    private function installEventCapture(): void
    {
        $this->recordedEvents = [];

        $provider = new ListenerProvider();
        // Catch-all: a listener on BaseEvent receives every subclass (InheritanceResolver
        // walks parents), so we record all dispatched RBAC domain events.
        $provider->addListener(BaseEvent::class, function (BaseEvent $event): void {
            $this->recordedEvents[] = $event;
        });
        $eventService = new EventService(new EventDispatcher($provider), $provider);

        $container = new class ($eventService) implements ContainerInterface {
            public function __construct(private EventService $eventService)
            {
            }

            public function get(string $id): mixed
            {
                if ($id === EventService::class) {
                    return $this->eventService;
                }
                throw new class ('No entry for ' . $id)
                    extends \RuntimeException implements \Psr\Container\NotFoundExceptionInterface {
                };
            }

            public function has(string $id): bool
            {
                return $id === EventService::class;
            }
        };

        $this->context->setContainer($container);
    }

    /**
     * Captured events of a given class.
     *
     * @template T of BaseEvent
     * @param class-string<T> $class
     * @return list<T>
     */
    protected function eventsOfType(string $class): array
    {
        return array_values(array_filter(
            $this->recordedEvents,
            static fn(BaseEvent $e): bool => $e instanceof $class
        ));
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
