<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Auth\UserIdentity;
use Glueful\Extensions\Aegis\Controllers\RoleController;
use Glueful\Extensions\Aegis\Http\DTOs\RolePermissionsData;
use Glueful\Extensions\Aegis\Repositories\RolePermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Services\AuditService;
use Glueful\Extensions\Aegis\Services\RoleService;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The role↔permission endpoints wire RolePermissionRepository to HTTP: read a role's grants, add,
 * replace (sync), and revoke. Each validates the role exists and a well-formed body, and the
 * mutating ones audit the change.
 */
final class RolePermissionEndpointsTest extends TestCase
{
    public function test_get_permissions_returns_role_grants(): void
    {
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('findRecordByUuid')->with('role-1')->willReturn(['uuid' => 'role-1']);
        $rp = $this->createMock(RolePermissionRepository::class);
        $rp->expects(self::once())
            ->method('getRolePermissions')
            ->with('role-1')
            ->willReturn([['permission_uuid' => 'perm-1']]);

        $response = $this->controller($roles, $rp)->getPermissions($this->request('role-1'));

        self::assertSame(200, $response->getStatusCode());
    }

    public function test_get_permissions_404_when_role_missing(): void
    {
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('findRecordByUuid')->willReturn(null);
        $rp = $this->createMock(RolePermissionRepository::class);
        $rp->expects(self::never())->method('getRolePermissions');

        $response = $this->controller($roles, $rp)->getPermissions($this->request('missing'));

        self::assertSame(404, $response->getStatusCode());
    }

    public function test_assign_permissions_rejects_missing_array(): void
    {
        $roles = $this->createMock(RoleRepository::class);
        $rp = $this->createMock(RolePermissionRepository::class);
        $rp->expects(self::never())->method('batchAssignPermissions');

        $response = $this->controller($roles, $rp)
            ->assignPermissions(new RolePermissionsData([]), $this->request('role-1'));

        self::assertSame(422, $response->getStatusCode());
    }

    public function test_assign_permissions_batch_assigns_and_audits(): void
    {
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('findRecordByUuid')->willReturn(['uuid' => 'role-1']);
        $rp = $this->createMock(RolePermissionRepository::class);
        $rp->expects(self::once())
            ->method('batchAssignPermissions')
            ->with('role-1', ['perm-1', 'perm-2'])
            ->willReturn(['success' => 2, 'failed' => 0, 'assignments' => []]);
        $audit = $this->createMock(AuditService::class);
        $audit->expects(self::once())
            ->method('logSecurityEvent')
            ->with('role.permissions.assigned', self::anything(), 'real-admin');

        $response = $this->controller($roles, $rp, $audit)
            ->assignPermissions(new RolePermissionsData(['perm-1', 'perm-2']), $this->request('role-1'));

        self::assertSame(200, $response->getStatusCode());
    }

    public function test_replace_permissions_syncs_full_set(): void
    {
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('findRecordByUuid')->willReturn(['uuid' => 'role-1']);
        $rp = $this->createMock(RolePermissionRepository::class);
        $rp->expects(self::once())
            ->method('replaceRolePermissions')
            ->with('role-1', ['perm-1'])
            ->willReturn(true);
        $rp->method('getRolePermissions')->willReturn([['permission_uuid' => 'perm-1']]);

        $response = $this->controller($roles, $rp)
            ->replacePermissions(new RolePermissionsData(['perm-1']), $this->request('role-1'));

        self::assertSame(200, $response->getStatusCode());
    }

    public function test_revoke_permission_removes_grant(): void
    {
        $roles = $this->createMock(RoleRepository::class);
        $roles->method('findRecordByUuid')->willReturn(['uuid' => 'role-1']);
        $rp = $this->createMock(RolePermissionRepository::class);
        $rp->expects(self::once())
            ->method('revokePermissionFromRole')
            ->with('role-1', 'perm-1')
            ->willReturn(true);

        $response = $this->controller($roles, $rp)
            ->revokePermission($this->request('role-1', [], 'perm-1'));

        self::assertSame(200, $response->getStatusCode());
    }

    private function controller(
        RoleRepository $roles,
        RolePermissionRepository $rp,
        ?AuditService $audit = null,
    ): RoleController {
        return new RoleController(
            $this->createMock(RoleService::class),
            $roles,
            $rp,
            $audit ?? $this->createMock(AuditService::class),
        );
    }

    /** @param array<string,mixed> $body */
    private function request(string $roleUuid, array $body = [], string $permissionUuid = ''): Request
    {
        $request = Request::create('/x', 'POST', [], [], [], [], (string) json_encode($body));
        $request->attributes->set('uuid', $roleUuid);
        if ($permissionUuid !== '') {
            $request->attributes->set('permission_uuid', $permissionUuid);
        }
        $request->attributes->set('auth.user', new UserIdentity('real-admin', ['administrator']));

        return $request;
    }
}
