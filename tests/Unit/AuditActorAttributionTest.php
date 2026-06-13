<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Auth\UserIdentity;
use Glueful\Extensions\Aegis\Controllers\PermissionController;
use Glueful\Extensions\Aegis\Controllers\RoleController;
use Glueful\Extensions\Aegis\Models\Permission;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\UserPermissionRepository;
use Glueful\Extensions\Aegis\Services\AuditService;
use Glueful\Extensions\Aegis\Services\PermissionAssignmentService;
use Glueful\Extensions\Aegis\Services\RoleService;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * Privilege-change attribution must come from the authenticated identity (`auth.user`), never
 * from the request body, and every change must be audited. A request that tries to spoof
 * `assigned_by` is ignored; the audit records the real actor.
 */
final class AuditActorAttributionTest extends TestCase
{
    public function test_role_assignment_attributes_to_auth_user_and_audits(): void
    {
        $roleService = $this->createMock(RoleService::class);
        $roleService->expects(self::once())
            ->method('assignRoleToUser')
            ->with(
                'target-user',
                'role-1',
                self::callback(static fn(array $opts): bool => ($opts['assigned_by'] ?? null) === 'real-admin')
            )
            ->willReturn(true);

        $audit = $this->createMock(AuditService::class);
        $audit->expects(self::once())
            ->method('logRoleAssigned')
            ->with('target-user', 'role-1', self::anything(), 'real-admin');

        $controller = new RoleController($roleService, $this->createMock(RoleRepository::class), $audit);

        // Body tries to forge assigned_by; it must be ignored in favour of auth.user.
        $request = Request::create(
            '/x',
            'POST',
            [],
            [],
            [],
            [],
            (string) json_encode(['user_uuid' => 'target-user', 'assigned_by' => 'spoofed-attacker'])
        );
        $request->attributes->set('uuid', 'role-1');
        $request->attributes->set('auth.user', new UserIdentity('real-admin', ['administrator']));

        $response = $controller->assignToUser($request);

        self::assertSame(200, $response->getStatusCode());
    }

    public function test_batch_permission_assignment_attributes_to_auth_user_and_audits_successes(): void
    {
        $service = $this->createMock(PermissionAssignmentService::class);
        $service->expects(self::once())
            ->method('batchAssignPermissions')
            ->with(
                'target-user',
                self::isType('array'),
                self::callback(static fn(array $opts): bool => ($opts['granted_by'] ?? null) === 'real-admin')
            )
            ->willReturn([
                'total' => 1,
                'successful' => 1,
                'failed' => 0,
                'results' => [
                    ['permission' => 'posts.edit', 'resource' => 'posts:1', 'success' => true, 'error' => null],
                ],
            ]);

        $permissions = $this->createMock(PermissionRepository::class);
        $permissions->expects(self::once())
            ->method('findPermissionBySlug')
            ->with('posts.edit')
            ->willReturn(new Permission(['uuid' => 'permission-1', 'slug' => 'posts.edit']));

        $audit = $this->createMock(AuditService::class);
        $audit->expects(self::once())
            ->method('logPermissionAssigned')
            ->with(
                'target-user',
                'permission-1',
                self::callback(static fn(array $data): bool => ($data['resource'] ?? null) === 'posts:1'),
                'real-admin'
            );

        $controller = new PermissionController(
            $service,
            $permissions,
            $this->createMock(UserPermissionRepository::class),
            $audit
        );

        $request = $this->jsonRequest([
            'user_uuid' => 'target-user',
            'permissions' => [['permission' => 'posts.edit', 'resource' => 'posts:1']],
            'options' => ['granted_by' => 'spoofed-attacker'],
        ]);

        $response = $controller->batchAssign($request);

        self::assertSame(200, $response->getStatusCode());
    }

    public function test_batch_permission_revoke_audits_successes(): void
    {
        $service = $this->createMock(PermissionAssignmentService::class);
        $service->expects(self::once())
            ->method('batchRevokePermissions')
            ->with('target-user', ['posts.edit'])
            ->willReturn([
                'total' => 1,
                'successful' => 1,
                'failed' => 0,
                'results' => [
                    ['permission' => 'posts.edit', 'success' => true, 'error' => null],
                ],
            ]);

        $permissions = $this->createMock(PermissionRepository::class);
        $permissions->expects(self::once())
            ->method('findPermissionBySlug')
            ->with('posts.edit')
            ->willReturn(new Permission(['uuid' => 'permission-1', 'slug' => 'posts.edit']));

        $audit = $this->createMock(AuditService::class);
        $audit->expects(self::once())
            ->method('logPermissionRevoked')
            ->with('target-user', 'permission-1', 'real-admin');

        $controller = new PermissionController(
            $service,
            $permissions,
            $this->createMock(UserPermissionRepository::class),
            $audit
        );

        $request = $this->jsonRequest([
            'user_uuid' => 'target-user',
            'permission_slugs' => ['posts.edit'],
        ]);

        $response = $controller->batchRevoke($request);

        self::assertSame(200, $response->getStatusCode());
    }

    public function test_bulk_role_delete_audits_successes(): void
    {
        $roleService = $this->createMock(RoleService::class);
        $roleService->expects(self::once())
            ->method('deleteRole')
            ->with('role-1', false)
            ->willReturn(true);

        $roles = $this->createMock(RoleRepository::class);
        $roles->expects(self::once())
            ->method('findRecordByUuid')
            ->with('role-1')
            ->willReturn(['uuid' => 'role-1', 'slug' => 'editor']);

        $audit = $this->createMock(AuditService::class);
        $audit->expects(self::once())
            ->method('logRoleDeleted')
            ->with('role-1', ['uuid' => 'role-1', 'slug' => 'editor'], 'real-admin');

        $controller = new RoleController($roleService, $roles, $audit);
        $response = $controller->bulk($this->jsonRequest(['action' => 'delete', 'role_ids' => ['role-1']]));

        self::assertSame(200, $response->getStatusCode());
    }

    public function test_bulk_role_status_update_audits_successes(): void
    {
        $roleService = $this->createMock(RoleService::class);
        $roleService->expects(self::once())
            ->method('updateRole')
            ->with('role-1', ['status' => 'inactive'], 'real-admin')
            ->willReturn(true);

        $roles = $this->createMock(RoleRepository::class);
        $roles->expects(self::exactly(2))
            ->method('findRecordByUuid')
            ->with('role-1')
            ->willReturnOnConsecutiveCalls(
                ['uuid' => 'role-1', 'slug' => 'editor', 'status' => 'active'],
                ['uuid' => 'role-1', 'slug' => 'editor', 'status' => 'inactive']
            );

        $audit = $this->createMock(AuditService::class);
        $audit->expects(self::once())
            ->method('logRoleUpdated')
            ->with(
                'role-1',
                ['uuid' => 'role-1', 'slug' => 'editor', 'status' => 'active'],
                ['uuid' => 'role-1', 'slug' => 'editor', 'status' => 'inactive'],
                'real-admin'
            );

        $controller = new RoleController($roleService, $roles, $audit);
        $response = $controller->bulk($this->jsonRequest(['action' => 'deactivate', 'role_ids' => ['role-1']]));

        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function jsonRequest(array $payload): Request
    {
        $request = Request::create('/x', 'POST', [], [], [], [], (string) json_encode($payload));
        $request->attributes->set('auth.user', new UserIdentity('real-admin', ['administrator']));

        return $request;
    }
}
