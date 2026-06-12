<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Auth\Contracts\UserProviderInterface;
use Glueful\Auth\UserIdentity;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RolePermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Services\BootstrapAdminService;
use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;

/**
 * Integration: BootstrapAdminService against the SQLite harness (extended with user_roles) and a
 * fake UserProvider (so Aegis stays decoupled from glueful/users). The catalog is pre-seeded
 * (the real command would have synced it).
 */
final class BootstrapAdminServiceTest extends AegisTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // user_roles now ships in the base harness schema (AegisTestCase::createSchema).
        $this->seedPermission(['slug' => 'users.read', 'name' => 'Read users', 'managed_by' => 'glueful/users']);
    }

    /** @param array<string,string> $identifierToUuid */
    private function service(array $identifierToUuid): BootstrapAdminService
    {
        $users = new class ($identifierToUuid) implements UserProviderInterface {
            /** @param array<string,string> $map */
            public function __construct(private array $map)
            {
            }
            public function findByUuid(string $uuid): ?UserIdentity
            {
                return in_array($uuid, $this->map, true) ? new UserIdentity($uuid) : null;
            }
            public function findByLogin(string $identifier): ?UserIdentity
            {
                $uuid = $this->map[$identifier] ?? null;
                return $uuid !== null ? new UserIdentity($uuid) : null;
            }
            public function verifyCredentials(string $identifier, string $password): ?UserIdentity
            {
                return null;
            }
        };

        // boot() calls initialize() in a real app; here we init with caching off so the
        // (cache-less) harness doesn't hit the distributed-cache invalidation path.
        $provider = $this->makeProvider();
        $provider->initialize(['cache_enabled' => false]);

        return new BootstrapAdminService(
            $users,
            new RoleRepository(),
            new PermissionRepository(),
            new RolePermissionRepository(),
            $provider,
        );
    }

    /** @return string[] role slugs assigned to a user */
    private function userRoleSlugs(string $userUuid): array
    {
        // user_roles has no deleted_at column (see migrations/001) — assignments
        // are hard-deleted on revoke.
        $stmt = $this->connection->getPDO()->prepare(
            'SELECT r.slug FROM user_roles ur JOIN roles r ON r.uuid = ur.role_uuid
             WHERE ur.user_uuid = ?'
        );
        $stmt->execute([$userUuid]);
        return array_map(static fn($r) => (string) $r['slug'], $stmt->fetchAll(\PDO::FETCH_ASSOC));
    }

    public function test_happy_path_creates_role_grants_users_read_and_assigns(): void
    {
        $svc = $this->service(['jane@example.com' => 'user-1']);

        $result = $svc->bootstrap('jane@example.com', 'admin', ['users.read'], false);

        self::assertSame('user-1', $result->userUuid);
        self::assertTrue($result->roleCreated, 'admin role created');
        self::assertSame(['users.read'], $result->granted);
        self::assertTrue($this->roleExists('admin'));
        self::assertSame(['users.read'], $this->roleGrantSlugs('admin'));
        self::assertSame(['admin'], $this->userRoleSlugs('user-1'));
    }

    public function test_reruns_are_additive_and_idempotent(): void
    {
        $svc = $this->service(['user-1' => 'user-1']);
        $svc->bootstrap('user-1', 'admin', ['users.read'], false);

        $second = $svc->bootstrap('user-1', 'admin', ['users.read'], false);

        self::assertFalse($second->roleCreated, 'role reused');
        self::assertSame([], $second->granted, 'already-present permission is not re-reported');
        self::assertSame(['users.read'], $this->roleGrantSlugs('admin'), 'no duplicate grant');
        self::assertSame(['admin'], $this->userRoleSlugs('user-1'), 'no duplicate assignment');
    }

    public function test_unknown_permission_fails_loudly(): void
    {
        $svc = $this->service(['user-1' => 'user-1']);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unknown permission');
        $svc->bootstrap('user-1', 'admin', ['does.not.exist'], false);
    }

    public function test_unknown_user_fails_loudly(): void
    {
        $svc = $this->service([]); // no users resolve

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('User not found');
        $svc->bootstrap('ghost@example.com', 'admin', ['users.read'], false);
    }

    public function test_dry_run_writes_nothing(): void
    {
        $svc = $this->service(['user-1' => 'user-1']);

        $result = $svc->bootstrap('user-1', 'admin', ['users.read'], true);

        self::assertTrue($result->dryRun);
        self::assertSame(['users.read'], $result->requested);
        self::assertFalse($this->roleExists('admin'), 'dry-run created no role');
        self::assertSame([], $this->userRoleSlugs('user-1'), 'dry-run assigned nothing');
    }
}
