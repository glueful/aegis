<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Auth\UserIdentity;
use Glueful\Extensions\Aegis\Controllers\RoleController;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Services\AuditService;
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
}
