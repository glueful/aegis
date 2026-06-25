<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\Events\PermissionAssignedEvent;
use Glueful\Extensions\Aegis\Events\PermissionRevokedEvent;
use Glueful\Extensions\Aegis\Repositories\UserPermissionRepository;
use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;

/**
 * Asserts UserPermissionRepository emits semantic RBAC events. The grant chokepoint is the
 * overridden create(); revokes guard on actual deletion.
 */
final class UserPermissionEventsTest extends AegisTestCase
{
    private function repo(): UserPermissionRepository
    {
        return new UserPermissionRepository(null, $this->context);
    }

    public function test_grant_emits_one_permission_assigned_event(): void
    {
        $this->repo()->create([
            'user_uuid' => 'user-1',
            'permission_uuid' => 'perm-1',
            'granted_by' => 'admin',
        ]);

        $events = $this->eventsOfType(PermissionAssignedEvent::class);
        self::assertCount(1, $events);
        self::assertSame('user-1', $events[0]->userUuid);
        self::assertSame('perm-1', $events[0]->permissionUuid);
        self::assertSame('admin', $events[0]->options['granted_by'] ?? null);
    }

    public function test_scoped_grant_carries_decoded_resource_filter(): void
    {
        $filter = ['resource' => 'posts', 'ids' => ['p1', 'p2']];
        $this->repo()->create([
            'user_uuid' => 'user-1',
            'permission_uuid' => 'perm-1',
            'resource_filter' => json_encode($filter),
        ]);

        $events = $this->eventsOfType(PermissionAssignedEvent::class);
        self::assertCount(1, $events);
        $rf = $events[0]->options['resource_filter'] ?? null;
        self::assertIsArray($rf, 'scoped grant must carry the decoded resource_filter');
        self::assertSame($filter, $rf);
        self::assertNotSame('*', $rf, 'scope must not be lost/flattened to a wildcard');
    }

    public function test_revoke_existing_emits_one_permission_revoked_event(): void
    {
        $repo = $this->repo();
        $repo->create(['user_uuid' => 'user-1', 'permission_uuid' => 'perm-1']);
        $this->recordedEvents = [];

        $deleted = $repo->revokeUserPermission('user-1', 'perm-1');

        self::assertTrue($deleted);
        $events = $this->eventsOfType(PermissionRevokedEvent::class);
        self::assertCount(1, $events);
        self::assertSame('user-1', $events[0]->userUuid);
        self::assertSame('perm-1', $events[0]->permissionUuid);
    }

    public function test_revoke_absent_pair_emits_zero_events(): void
    {
        $deleted = $this->repo()->revokeUserPermission('user-1', 'nope');

        self::assertFalse($deleted);
        self::assertCount(0, $this->eventsOfType(PermissionRevokedEvent::class));
    }

    public function test_revoke_all_emits_one_event_per_removed_permission(): void
    {
        $repo = $this->repo();
        $repo->create(['user_uuid' => 'user-1', 'permission_uuid' => 'perm-1']);
        $repo->create(['user_uuid' => 'user-1', 'permission_uuid' => 'perm-2']);
        $this->recordedEvents = [];

        $repo->revokeAllUserPermissions('user-1');

        $events = $this->eventsOfType(PermissionRevokedEvent::class);
        self::assertCount(2, $events);
        $perms = array_map(static fn(PermissionRevokedEvent $e) => $e->permissionUuid, $events);
        sort($perms);
        self::assertSame(['perm-1', 'perm-2'], $perms);
    }

    public function test_revoke_all_with_no_permissions_emits_zero_events(): void
    {
        $this->repo()->revokeAllUserPermissions('user-nobody');

        self::assertCount(0, $this->eventsOfType(PermissionRevokedEvent::class));
    }
}
