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

    public function test_replace_with_identical_set_writes_nothing(): void
    {
        $repo = $this->repo();
        $repo->assignPermissionToRole('role-1', 'perm-1');
        $repo->assignPermissionToRole('role-1', 'perm-2');
        $repo->assignPermissionToRole('role-1', 'perm-3');
        $before = $this->liveLinks('role-1');
        $this->recordedEvents = [];

        $ok = $repo->replaceRolePermissions('role-1', ['perm-1', 'perm-2', 'perm-3']);

        self::assertTrue($ok);
        self::assertCount(0, $this->eventsOfType(RolePermissionAssignedEvent::class), 'no assigns for an unchanged set');
        self::assertCount(0, $this->eventsOfType(RolePermissionRevokedEvent::class), 'no revokes for an unchanged set');
        self::assertSame(0, $this->tombstoneCount('role-1'), 'no new soft-delete tombstones');
        self::assertSame($before, $this->liveLinks('role-1'), 'live rows untouched (same link uuids)');
    }

    public function test_replace_adds_only_new_and_keeps_existing(): void
    {
        $repo = $this->repo();
        $repo->assignPermissionToRole('role-1', 'perm-1');
        $repo->assignPermissionToRole('role-1', 'perm-2');
        $kept = $this->liveLinks('role-1');
        $this->recordedEvents = [];

        $ok = $repo->replaceRolePermissions('role-1', ['perm-1', 'perm-2', 'perm-3']);

        self::assertTrue($ok);
        $assigned = $this->eventsOfType(RolePermissionAssignedEvent::class);
        self::assertCount(1, $assigned, 'only the genuinely new link is assigned');
        self::assertSame('perm-3', $assigned[0]->permissionUuid);
        self::assertCount(0, $this->eventsOfType(RolePermissionRevokedEvent::class));
        self::assertSame(0, $this->tombstoneCount('role-1'), 'untouched links are not revoked');

        $after = $this->liveLinks('role-1');
        self::assertSame($kept['perm-1'], $after['perm-1'] ?? null, 'perm-1 keeps its original row');
        self::assertSame($kept['perm-2'], $after['perm-2'] ?? null, 'perm-2 keeps its original row');
        self::assertArrayHasKey('perm-3', $after);
    }

    public function test_replace_removes_only_absent_and_keeps_rest(): void
    {
        $repo = $this->repo();
        $repo->assignPermissionToRole('role-1', 'perm-1');
        $repo->assignPermissionToRole('role-1', 'perm-2');
        $repo->assignPermissionToRole('role-1', 'perm-3');
        $kept = $this->liveLinks('role-1');
        $this->recordedEvents = [];

        $ok = $repo->replaceRolePermissions('role-1', ['perm-1', 'perm-2']);

        self::assertTrue($ok);
        $revoked = $this->eventsOfType(RolePermissionRevokedEvent::class);
        self::assertCount(1, $revoked, 'only the absent link is revoked');
        self::assertSame('perm-3', $revoked[0]->permissionUuid);
        self::assertCount(0, $this->eventsOfType(RolePermissionAssignedEvent::class));

        $after = $this->liveLinks('role-1');
        self::assertSame(['perm-1', 'perm-2'], array_keys($after));
        self::assertSame($kept['perm-1'], $after['perm-1'], 'kept links retain their original rows');
        self::assertSame($kept['perm-2'], $after['perm-2']);
    }

    public function test_replace_with_overlap_touches_only_the_diff(): void
    {
        // [perm-1, perm-2] -> [perm-2, perm-3]: perm-1 removed, perm-3 added, perm-2 kept.
        $repo = $this->repo();
        $repo->assignPermissionToRole('role-1', 'perm-1');
        $repo->assignPermissionToRole('role-1', 'perm-2');
        $keptUuid = $this->liveLinks('role-1')['perm-2'];
        $this->recordedEvents = [];

        $ok = $repo->replaceRolePermissions('role-1', ['perm-2', 'perm-3']);

        self::assertTrue($ok);
        $revoked = $this->eventsOfType(RolePermissionRevokedEvent::class);
        $assigned = $this->eventsOfType(RolePermissionAssignedEvent::class);
        self::assertCount(1, $revoked);
        self::assertSame('perm-1', $revoked[0]->permissionUuid);
        self::assertCount(1, $assigned);
        self::assertSame('perm-3', $assigned[0]->permissionUuid);

        $after = $this->liveLinks('role-1');
        self::assertSame(['perm-2', 'perm-3'], array_keys($after));
        self::assertSame($keptUuid, $after['perm-2'], 'the overlapping link is not churned');
    }

    public function test_replace_empty_revokes_all(): void
    {
        $repo = $this->repo();
        $repo->assignPermissionToRole('role-1', 'perm-1');
        $repo->assignPermissionToRole('role-1', 'perm-2');
        $this->recordedEvents = [];

        $ok = $repo->replaceRolePermissions('role-1', []);

        self::assertTrue($ok);
        self::assertCount(2, $this->eventsOfType(RolePermissionRevokedEvent::class));
        self::assertCount(0, $this->eventsOfType(RolePermissionAssignedEvent::class));
        self::assertSame([], $this->liveLinks('role-1'));
    }

    public function test_replace_dedupes_duplicate_input(): void
    {
        $repo = $this->repo();
        $this->recordedEvents = [];

        $ok = $repo->replaceRolePermissions('role-1', ['perm-1', 'perm-1', 'perm-2']);

        self::assertTrue($ok);
        self::assertCount(2, $this->eventsOfType(RolePermissionAssignedEvent::class), 'duplicate input collapses to one assign each');
        self::assertSame(['perm-1', 'perm-2'], array_keys($this->liveLinks('role-1')));
        self::assertSame(2, $this->liveRowCount('role-1'), 'exactly one live row per permission');
    }

    /**
     * Live (non-tombstoned) role→permission links, as permission_uuid => link uuid, sorted by key.
     *
     * @return array<string, string>
     */
    private function liveLinks(string $roleUuid): array
    {
        $stmt = $this->connection->getPDO()->prepare(
            'SELECT permission_uuid, uuid FROM role_permissions WHERE role_uuid = ? AND deleted_at IS NULL'
        );
        $stmt->execute([$roleUuid]);
        $out = [];
        foreach ($stmt->fetchAll(\PDO::FETCH_ASSOC) as $row) {
            $out[(string) $row['permission_uuid']] = (string) $row['uuid'];
        }
        ksort($out);
        return $out;
    }

    private function liveRowCount(string $roleUuid): int
    {
        $stmt = $this->connection->getPDO()->prepare(
            'SELECT COUNT(*) FROM role_permissions WHERE role_uuid = ? AND deleted_at IS NULL'
        );
        $stmt->execute([$roleUuid]);
        return (int) $stmt->fetchColumn();
    }

    private function tombstoneCount(string $roleUuid): int
    {
        $stmt = $this->connection->getPDO()->prepare(
            'SELECT COUNT(*) FROM role_permissions WHERE role_uuid = ? AND deleted_at IS NOT NULL'
        );
        $stmt->execute([$roleUuid]);
        return (int) $stmt->fetchColumn();
    }
}
