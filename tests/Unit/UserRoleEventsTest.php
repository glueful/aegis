<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\Events\RoleAssignedEvent;
use Glueful\Extensions\Aegis\Events\RoleRevokedEvent;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;
use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;

/**
 * Asserts UserRoleRepository emits semantic RBAC events from the (context-bearing) harness.
 * Repos are constructed with $this->context so BaseRepository::dispatchEvent() actually fires.
 */
final class UserRoleEventsTest extends AegisTestCase
{
    private function repo(): UserRoleRepository
    {
        return new UserRoleRepository(null, $this->context);
    }

    public function test_assign_emits_one_role_assigned_event(): void
    {
        $this->repo()->assignRole('user-1', 'role-1', ['granted_by' => 'admin']);

        $events = $this->eventsOfType(RoleAssignedEvent::class);
        self::assertCount(1, $events);
        self::assertSame('user-1', $events[0]->userUuid);
        self::assertSame('role-1', $events[0]->roleUuid);
        self::assertSame('admin', $events[0]->options['granted_by'] ?? null);
    }

    public function test_duplicate_assign_emits_zero_additional_events(): void
    {
        $repo = $this->repo();
        $repo->assignRole('user-1', 'role-1');
        $this->recordedEvents = []; // reset; the no-op assign below must emit nothing

        $repo->assignRole('user-1', 'role-1');

        self::assertCount(0, $this->eventsOfType(RoleAssignedEvent::class));
    }

    public function test_revoke_existing_emits_one_role_revoked_event(): void
    {
        $repo = $this->repo();
        $repo->assignRole('user-1', 'role-1');
        $this->recordedEvents = [];

        $deleted = $repo->revokeRole('user-1', 'role-1');

        self::assertTrue($deleted);
        $events = $this->eventsOfType(RoleRevokedEvent::class);
        self::assertCount(1, $events);
        self::assertSame('user-1', $events[0]->userUuid);
        self::assertSame('role-1', $events[0]->roleUuid);
    }

    public function test_revoke_absent_pair_emits_zero_events(): void
    {
        $deleted = $this->repo()->revokeRole('user-1', 'nope');

        self::assertFalse($deleted);
        self::assertCount(0, $this->eventsOfType(RoleRevokedEvent::class));
    }

    public function test_revoke_all_emits_one_event_per_removed_role(): void
    {
        $repo = $this->repo();
        $repo->assignRole('user-1', 'role-1');
        $repo->assignRole('user-1', 'role-2');
        $this->recordedEvents = [];

        $repo->revokeAllUserRoles('user-1');

        $events = $this->eventsOfType(RoleRevokedEvent::class);
        self::assertCount(2, $events);
        $roleUuids = array_map(static fn(RoleRevokedEvent $e) => $e->roleUuid, $events);
        sort($roleUuids);
        self::assertSame(['role-1', 'role-2'], $roleUuids);
    }

    public function test_revoke_all_with_no_roles_emits_zero_events(): void
    {
        $this->repo()->revokeAllUserRoles('user-nobody');

        self::assertCount(0, $this->eventsOfType(RoleRevokedEvent::class));
    }
}
