<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\Events\RolePermissionAssignedEvent;
use Glueful\Extensions\Aegis\Events\RolePermissionRevokedEvent;
use Glueful\Extensions\Aegis\Repositories\RolePermissionRepository;
use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;

/**
 * Asserts RolePermissionRepository emits semantic RBAC events, including the
 * replaceRolePermissions() fix that routes removals through the semantic revoke method.
 */
final class RolePermissionEventsTest extends AegisTestCase
{
    private function repo(): RolePermissionRepository
    {
        return new RolePermissionRepository(null, $this->context);
    }

    public function test_assign_emits_one_role_permission_assigned_event(): void
    {
        $this->repo()->assignPermissionToRole('role-1', 'perm-1', ['granted_by' => 'admin']);

        $events = $this->eventsOfType(RolePermissionAssignedEvent::class);
        self::assertCount(1, $events);
        self::assertSame('role-1', $events[0]->roleUuid);
        self::assertSame('perm-1', $events[0]->permissionUuid);
        self::assertSame('admin', $events[0]->options['granted_by'] ?? null);
    }

    public function test_duplicate_assign_emits_zero_additional_events(): void
    {
        $repo = $this->repo();
        $repo->assignPermissionToRole('role-1', 'perm-1');
        $this->recordedEvents = [];

        $repo->assignPermissionToRole('role-1', 'perm-1');

        self::assertCount(0, $this->eventsOfType(RolePermissionAssignedEvent::class));
    }

    public function test_revoke_existing_emits_one_event(): void
    {
        $repo = $this->repo();
        $repo->assignPermissionToRole('role-1', 'perm-1');
        $this->recordedEvents = [];

        $repo->revokePermissionFromRole('role-1', 'perm-1');

        $events = $this->eventsOfType(RolePermissionRevokedEvent::class);
        self::assertCount(1, $events);
        self::assertSame('role-1', $events[0]->roleUuid);
        self::assertSame('perm-1', $events[0]->permissionUuid);
    }

    public function test_revoke_absent_link_emits_zero_events(): void
    {
        // revokePermissionFromRole() returns true even when absent (so the batch tally lies),
        // but the dispatch is guarded by the actual delete() — assert ZERO events here.
        $result = $this->repo()->revokePermissionFromRole('role-1', 'never-linked');

        self::assertTrue($result);
        self::assertCount(0, $this->eventsOfType(RolePermissionRevokedEvent::class));
    }

    public function test_replace_emits_revoke_per_removed_and_assign_per_added(): void
    {
        $repo = $this->repo();
        // Seed two existing links.
        $repo->assignPermissionToRole('role-1', 'perm-1');
        $repo->assignPermissionToRole('role-1', 'perm-2');
        $this->recordedEvents = [];

        // Replace with a different set: keep none, add perm-3 and perm-4.
        $ok = $repo->replaceRolePermissions('role-1', ['perm-3', 'perm-4']);

        self::assertTrue($ok);

        $revoked = $this->eventsOfType(RolePermissionRevokedEvent::class);
        $assigned = $this->eventsOfType(RolePermissionAssignedEvent::class);

        self::assertCount(2, $revoked, 'one revoke per removed link');
        self::assertCount(2, $assigned, 'one assign per added link');

        $removed = array_map(static fn(RolePermissionRevokedEvent $e) => $e->permissionUuid, $revoked);
        sort($removed);
        self::assertSame(['perm-1', 'perm-2'], $removed);

        $added = array_map(static fn(RolePermissionAssignedEvent $e) => $e->permissionUuid, $assigned);
        sort($added);
        self::assertSame(['perm-3', 'perm-4'], $added);
    }
}
