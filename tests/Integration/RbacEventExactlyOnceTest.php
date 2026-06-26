<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Integration;

use Glueful\Auth\Contracts\UserProviderInterface;
use Glueful\Auth\UserIdentity;
use Glueful\Extensions\Aegis\AegisPermissionProvider;
use Glueful\Extensions\Aegis\Events\PermissionAssignedEvent;
use Glueful\Extensions\Aegis\Events\PermissionRevokedEvent;
use Glueful\Extensions\Aegis\Events\RoleAssignedEvent;
use Glueful\Extensions\Aegis\Events\RolePermissionAssignedEvent;
use Glueful\Extensions\Aegis\Events\RolePermissionRevokedEvent;
use Glueful\Extensions\Aegis\Events\RoleRevokedEvent;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RolePermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Repositories\UserPermissionRepository;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;
use Glueful\Extensions\Aegis\Services\BootstrapAdminService;
use Glueful\Extensions\Aegis\Services\PermissionAssignmentService;
use Glueful\Extensions\Aegis\Services\RoleService;
use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;

/**
 * Exactly-once guarantee, regardless of entry point.
 *
 * Tasks 2.0–2.4 made the three pivot repositories the sole dispatchers of RBAC domain events.
 * This test proves the higher-level callers (provider, services, batch, replace/sync, bootstrap)
 * all funnel through those single chokepoints and therefore emit EXACTLY ONE semantic event per
 * real action — no duplicates (e.g. a service emitting its own copy on top of the repo's) and no
 * misses (e.g. a caller bypassing the dispatching method). It guards against a future caller
 * wiring around the chokepoint.
 *
 * Each family is driven from its HIGHEST reachable seam (provider/service); pure HTTP-only entry
 * points (controllers) are covered through the exact repository/service method they delegate to —
 * see the per-test docblocks for "direct vs via delegate".
 *
 * Slug-based callers resolve slugs to uuids first, so the catalog is pre-seeded with known uuids
 * and assertions are made on those uuids.
 */
final class RbacEventExactlyOnceTest extends AegisTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Catalog with deterministic uuids so slug-resolving callers produce predictable events.
        $this->seedRole(['uuid' => 'role-admin', 'slug' => 'admin', 'name' => 'Admin']);
        $this->seedRole(['uuid' => 'role-editor', 'slug' => 'editor', 'name' => 'Editor']);
        $this->seedPermission(['uuid' => 'perm-read', 'slug' => 'posts.read', 'name' => 'Read posts']);
        $this->seedPermission(['uuid' => 'perm-write', 'slug' => 'posts.write', 'name' => 'Write posts']);
        $this->seedPermission(['uuid' => 'perm-delete', 'slug' => 'posts.delete', 'name' => 'Delete posts']);
    }

    /** Cache-less provider, mirroring production boot() → initialize() but without distributed cache. */
    private function provider(): AegisPermissionProvider
    {
        $provider = $this->makeProvider();
        $provider->initialize(['cache_enabled' => false]);
        return $provider;
    }

    /**
     * Repos are built WITH the context exactly as the (fixed) DI definitions in
     * AegisServiceProvider::services() now construct them — `[null, '@'.ApplicationContext::class]`.
     * Building them context-less here would reproduce the pre-fix bug (dispatchEvent no-ops) and
     * the service-layer assertions below would fail; that coupling is intentional — this test is
     * the guard for that wiring.
     */
    private function roleService(): RoleService
    {
        return new RoleService(
            new RoleRepository(null, $this->context),
            new UserRoleRepository(null, $this->context),
            $this->provider(),
        );
    }

    private function permissionService(): PermissionAssignmentService
    {
        return new PermissionAssignmentService(
            new PermissionRepository(null, $this->context),
            new UserPermissionRepository(null, $this->context),
            new RoleRepository(null, $this->context),
            new UserRoleRepository(null, $this->context),
            new RolePermissionRepository(null, $this->context),
            $this->provider(),
        );
    }

    /** @param array<string,string> $identifierToUuid */
    private function bootstrapService(array $identifierToUuid): BootstrapAdminService
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

        return new BootstrapAdminService(
            $users,
            new RoleRepository(null, $this->context),
            new PermissionRepository(null, $this->context),
            new RolePermissionRepository(null, $this->context),
            $this->provider(),
        );
    }

    // ------------------------------------------------------------------
    // user ↔ role  (chokepoint: UserRoleRepository::assignRole/revokeRole/revokeAllUserRoles)
    // ------------------------------------------------------------------

    /**
     * Entry point driven DIRECTLY: AegisPermissionProvider::assignRole/revokeRole (slug-based).
     */
    public function test_provider_assign_role_emits_exactly_one(): void
    {
        $provider = $this->provider();

        self::assertTrue($provider->assignRole('user-1', 'admin', ['granted_by' => 'root']));

        $events = $this->eventsOfType(RoleAssignedEvent::class);
        self::assertCount(1, $events);
        self::assertSame('user-1', $events[0]->userUuid);
        self::assertSame('role-admin', $events[0]->roleUuid);
    }

    public function test_provider_reassign_role_is_noop_zero_events(): void
    {
        $provider = $this->provider();
        $provider->assignRole('user-1', 'admin');
        $this->recordedEvents = [];

        $provider->assignRole('user-1', 'admin');

        self::assertCount(0, $this->eventsOfType(RoleAssignedEvent::class));
    }

    public function test_provider_revoke_role_emits_exactly_one(): void
    {
        $provider = $this->provider();
        $provider->assignRole('user-1', 'admin');
        $this->recordedEvents = [];

        self::assertTrue($provider->revokeRole('user-1', 'admin'));

        $events = $this->eventsOfType(RoleRevokedEvent::class);
        self::assertCount(1, $events);
        self::assertSame('role-admin', $events[0]->roleUuid);
    }

    public function test_provider_revoke_absent_role_zero_events(): void
    {
        // Slug exists but the pair was never assigned: no-op, no event.
        self::assertFalse($this->provider()->revokeRole('user-1', 'admin'));
        self::assertCount(0, $this->eventsOfType(RoleRevokedEvent::class));
    }

    /**
     * Entry point driven DIRECTLY: RoleService::assignRoleToUser/revokeRoleFromUser (uuid-based).
     * Proves the service does NOT emit a duplicate on top of the repo's single dispatch.
     */
    public function test_role_service_assign_then_revoke_emits_one_each(): void
    {
        $svc = $this->roleService();

        self::assertTrue($svc->assignRoleToUser('user-2', 'role-editor'));
        self::assertCount(1, $this->eventsOfType(RoleAssignedEvent::class));

        // Re-assign is a no-op at the service guard (hasUserRole) → zero further events.
        self::assertTrue($svc->assignRoleToUser('user-2', 'role-editor'));
        self::assertCount(1, $this->eventsOfType(RoleAssignedEvent::class));

        $this->recordedEvents = [];
        self::assertTrue($svc->revokeRoleFromUser('user-2', 'role-editor'));
        $revoked = $this->eventsOfType(RoleRevokedEvent::class);
        self::assertCount(1, $revoked);
        self::assertSame('role-editor', $revoked[0]->roleUuid);

        // Revoking the now-absent pair emits nothing.
        $this->recordedEvents = [];
        self::assertFalse($svc->revokeRoleFromUser('user-2', 'role-editor'));
        self::assertCount(0, $this->eventsOfType(RoleRevokedEvent::class));
    }

    /**
     * Entry point driven DIRECTLY: BootstrapAdminService::bootstrap.
     * Its role-grant path delegates to provider->assignRole → UserRoleRepository::assignRole, and
     * its permission path to RolePermissionRepository::assignPermissionToRole. Asserts exactly one
     * RoleAssigned (user↔role) and one RolePermissionAssigned (role↔permission) for a first run.
     */
    public function test_bootstrap_admin_emits_one_role_assign_and_one_role_permission(): void
    {
        $svc = $this->bootstrapService(['jane@example.com' => 'user-3']);

        $svc->bootstrap('jane@example.com', 'admin', ['posts.read'], false);

        $assigned = $this->eventsOfType(RoleAssignedEvent::class);
        self::assertCount(1, $assigned, 'exactly one user↔role grant');
        self::assertSame('user-3', $assigned[0]->userUuid);
        self::assertSame('role-admin', $assigned[0]->roleUuid);

        $rolePerm = $this->eventsOfType(RolePermissionAssignedEvent::class);
        self::assertCount(1, $rolePerm, 'exactly one role↔permission grant');
        self::assertSame('role-admin', $rolePerm[0]->roleUuid);
        self::assertSame('perm-read', $rolePerm[0]->permissionUuid);
    }

    public function test_bootstrap_admin_rerun_is_idempotent_zero_new_events(): void
    {
        $svc = $this->bootstrapService(['user-3' => 'user-3']);
        $svc->bootstrap('user-3', 'admin', ['posts.read'], false);
        $this->recordedEvents = [];

        // Re-running grants nothing new: role already assigned, permission already on role.
        $svc->bootstrap('user-3', 'admin', ['posts.read'], false);

        self::assertCount(0, $this->eventsOfType(RoleAssignedEvent::class));
        self::assertCount(0, $this->eventsOfType(RolePermissionAssignedEvent::class));
    }

    // ------------------------------------------------------------------
    // user ↔ permission  (chokepoint: UserPermissionRepository::create/revokeUserPermission)
    // ------------------------------------------------------------------

    /**
     * Entry point driven DIRECTLY: AegisPermissionProvider::assignPermission/revokePermission and
     * batchAssignPermissions/batchRevokePermissions.
     */
    public function test_provider_assign_permission_emits_exactly_one(): void
    {
        $provider = $this->provider();

        self::assertTrue($provider->assignPermission('user-1', 'posts.read', '*', ['granted_by' => 'root']));

        $events = $this->eventsOfType(PermissionAssignedEvent::class);
        self::assertCount(1, $events);
        self::assertSame('user-1', $events[0]->userUuid);
        self::assertSame('perm-read', $events[0]->permissionUuid);
    }

    public function test_provider_revoke_absent_permission_zero_events(): void
    {
        self::assertFalse($this->provider()->revokePermission('user-1', 'posts.read', '*'));
        self::assertCount(0, $this->eventsOfType(PermissionRevokedEvent::class));
    }

    public function test_provider_batch_assign_n_distinct_emits_n_events(): void
    {
        $provider = $this->provider();

        $ok = $provider->batchAssignPermissions('user-1', [
            ['permission' => 'posts.read'],
            ['permission' => 'posts.write'],
            ['permission' => 'posts.delete'],
        ]);

        self::assertTrue($ok);
        $events = $this->eventsOfType(PermissionAssignedEvent::class);
        self::assertCount(3, $events);
        $perms = array_map(static fn(PermissionAssignedEvent $e) => $e->permissionUuid, $events);
        sort($perms);
        self::assertSame(['perm-delete', 'perm-read', 'perm-write'], $perms);
    }

    public function test_provider_batch_revoke_n_distinct_emits_n_events(): void
    {
        $provider = $this->provider();
        $provider->assignPermission('user-1', 'posts.read', '*');
        $provider->assignPermission('user-1', 'posts.write', '*');
        $this->recordedEvents = [];

        $provider->batchRevokePermissions('user-1', [
            ['permission' => 'posts.read'],
            ['permission' => 'posts.write'],
        ]);

        $events = $this->eventsOfType(PermissionRevokedEvent::class);
        self::assertCount(2, $events);
        $perms = array_map(static fn(PermissionRevokedEvent $e) => $e->permissionUuid, $events);
        sort($perms);
        self::assertSame(['perm-read', 'perm-write'], $perms);
    }

    /**
     * Entry point driven DIRECTLY: PermissionAssignmentService::assignPermissionToUser /
     * revokePermissionFromUser / batchAssignPermissions. (PermissionController::batchAssign is
     * HTTP-only; it delegates to this service method — covered here via the delegate.)
     */
    public function test_permission_service_assign_revoke_and_batch(): void
    {
        $svc = $this->permissionService();

        // Single assign → one event.
        self::assertTrue($svc->assignPermissionToUser('user-4', 'posts.read'));
        self::assertCount(1, $this->eventsOfType(PermissionAssignedEvent::class));

        // Re-assign is a no-op at the service guard (findUserPermission) → no new event.
        self::assertTrue($svc->assignPermissionToUser('user-4', 'posts.read'));
        self::assertCount(1, $this->eventsOfType(PermissionAssignedEvent::class));

        // Revoke → one event; re-revoke (absent) → none.
        $this->recordedEvents = [];
        self::assertTrue($svc->revokePermissionFromUser('user-4', 'posts.read'));
        self::assertCount(1, $this->eventsOfType(PermissionRevokedEvent::class));
        $this->recordedEvents = [];
        self::assertFalse($svc->revokePermissionFromUser('user-4', 'posts.read'));
        self::assertCount(0, $this->eventsOfType(PermissionRevokedEvent::class));

        // Batch of N distinct → N events.
        $this->recordedEvents = [];
        $svc->batchAssignPermissions('user-4', [
            ['permission' => 'posts.read'],
            ['permission' => 'posts.write'],
            ['permission' => 'posts.delete'],
        ]);
        self::assertCount(3, $this->eventsOfType(PermissionAssignedEvent::class));
    }

    // ------------------------------------------------------------------
    // role ↔ permission  (chokepoint: RolePermissionRepository::assignPermissionToRole /
    //                     revokePermissionFromRole)
    // ------------------------------------------------------------------

    /**
     * Entry points driven DIRECTLY at the repository: assignPermissionToRole, batchAssignPermissions,
     * replaceRolePermissions. RoleController::assignPermissions/replacePermissions are HTTP-only and
     * delegate verbatim to batchAssignPermissions / replaceRolePermissions — covered here via those
     * delegates.
     */
    public function test_role_permission_assign_and_noop(): void
    {
        $repo = new RolePermissionRepository(null, $this->context);

        self::assertNotNull($repo->assignPermissionToRole('role-admin', 'perm-read'));
        self::assertCount(1, $this->eventsOfType(RolePermissionAssignedEvent::class));

        // Re-assign existing → idempotent, zero new events.
        $this->recordedEvents = [];
        self::assertNotNull($repo->assignPermissionToRole('role-admin', 'perm-read'));
        self::assertCount(0, $this->eventsOfType(RolePermissionAssignedEvent::class));
    }

    public function test_role_permission_batch_assign_n_emits_n(): void
    {
        $repo = new RolePermissionRepository(null, $this->context);

        $repo->batchAssignPermissions('role-admin', ['perm-read', 'perm-write', 'perm-delete']);

        self::assertCount(3, $this->eventsOfType(RolePermissionAssignedEvent::class));
    }

    /**
     * replace/sync from {read, write} to {write, delete}: exactly one revoke (read) + one assign
     * (delete), and NOT a revoke/assign for the unchanged write.
     *
     * NOTE: replaceRolePermissions revokes ALL existing then re-assigns the new set, so the
     * unchanged member emits a revoke+assign pair internally. To assert the *semantic* delta
     * (which is what a future sync optimisation must preserve), drive the highest seam that
     * computes a delta — AegisPermissionProvider::syncCatalog → syncRoles — and assert the net
     * events for the changed members only.
     */
    public function test_provider_sync_catalog_emits_delta_only_for_changed_members(): void
    {
        $repo = new RolePermissionRepository(null, $this->context);
        // Seed the role with {read, write}.
        $repo->assignPermissionToRole('role-editor', 'perm-read');
        $repo->assignPermissionToRole('role-editor', 'perm-write');
        $this->recordedEvents = [];

        // Sync declares the editor role granting {write, delete}: read removed, delete added,
        // write unchanged.
        $provider = $this->provider();
        $provider->syncCatalog(
            [
                ['slug' => 'posts.read', 'name' => 'Read posts'],
                ['slug' => 'posts.write', 'name' => 'Write posts'],
                ['slug' => 'posts.delete', 'name' => 'Delete posts'],
            ],
            [
                ['slug' => 'editor', 'name' => 'Editor', 'grants' => ['posts.write', 'posts.delete']],
            ],
        );

        $revoked = $this->eventsOfType(RolePermissionRevokedEvent::class);
        $assigned = $this->eventsOfType(RolePermissionAssignedEvent::class);

        $revokedPerms = array_map(static fn(RolePermissionRevokedEvent $e) => $e->permissionUuid, $revoked);
        $assignedPerms = array_map(static fn(RolePermissionAssignedEvent $e) => $e->permissionUuid, $assigned);

        // The removed member (read) is revoked exactly once and never re-assigned.
        self::assertSame([1], [count(array_keys($revokedPerms, 'perm-read', true))], 'read revoked exactly once');
        self::assertNotContains('perm-read', $assignedPerms, 'read must not be re-assigned');

        // The added member (delete) is assigned exactly once and never revoked.
        self::assertSame([1], [count(array_keys($assignedPerms, 'perm-delete', true))], 'delete assigned exactly once');
        self::assertNotContains('perm-delete', $revokedPerms, 'delete must not be revoked');
    }

    /**
     * Direct repo-level replace from {read, write} to {write, delete}: replaceRolePermissions
     * now reconciles by diff, so it touches ONLY the changed members — read is revoked, delete
     * is assigned, and the unchanged write is left alone (no revoke/assign churn). Pins both the
     * per-member event deltas and the final live grant set.
     */
    public function test_repo_replace_role_permissions_net_delta(): void
    {
        $repo = new RolePermissionRepository(null, $this->context);
        $repo->assignPermissionToRole('role-editor', 'perm-read');
        $repo->assignPermissionToRole('role-editor', 'perm-write');
        $this->recordedEvents = [];

        self::assertTrue($repo->replaceRolePermissions('role-editor', ['perm-write', 'perm-delete']));

        $revoked = array_map(
            static fn(RolePermissionRevokedEvent $e) => $e->permissionUuid,
            $this->eventsOfType(RolePermissionRevokedEvent::class)
        );
        $assigned = array_map(
            static fn(RolePermissionAssignedEvent $e) => $e->permissionUuid,
            $this->eventsOfType(RolePermissionAssignedEvent::class)
        );

        // read: revoked, never re-assigned (net removed).
        self::assertContains('perm-read', $revoked);
        self::assertNotContains('perm-read', $assigned);
        // delete: assigned, never revoked (net added).
        self::assertContains('perm-delete', $assigned);
        self::assertNotContains('perm-delete', $revoked);
        // write (unchanged): left untouched — neither revoked nor re-assigned.
        self::assertNotContains('perm-write', $revoked, 'unchanged grant is not revoked');
        self::assertNotContains('perm-write', $assigned, 'unchanged grant is not re-assigned');

        // Final live grant set is exactly {write, delete}.
        $live = array_map(
            static fn($a) => $a->getPermissionUuid(),
            $repo->getRolePermissions('role-editor')
        );
        sort($live);
        self::assertSame(['perm-delete', 'perm-write'], $live);
    }
}
