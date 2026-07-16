<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\Models\UserRole;
use PHPUnit\Framework\TestCase;

/**
 * matchesScope() is the fail-closed core of scoped-role authorization:
 * - an UNSCOPED assignment is global and matches any request context;
 * - a SCOPED assignment is a constraint set — every key it declares must be present and
 *   equal in the request context (assignment-constraints ⊆ request-context), so an empty
 *   request context never activates it, and extra request keys it does not constrain are
 *   irrelevant. The pre-fix implementation iterated the REQUEST keys instead, which made
 *   an empty request match every scoped assignment (fail-open).
 */
final class UserRoleScopeMatchingTest extends TestCase
{
    /** @param array<string, mixed>|null $scope */
    private function userRole(?array $scope): UserRole
    {
        return new UserRole([
            'uuid' => 'ur-1',
            'user_uuid' => 'user-1',
            'role_uuid' => 'role-1',
            'scope' => $scope !== null ? json_encode($scope) : null,
        ]);
    }

    public function test_unscoped_assignment_matches_anything(): void
    {
        $global = $this->userRole(null);
        self::assertTrue($global->matchesScope([]));
        self::assertTrue($global->matchesScope(['tenant_id' => 'tenant-a']));
    }

    public function test_scoped_assignment_fails_closed_on_empty_request_scope(): void
    {
        $scoped = $this->userRole(['tenant_id' => 'tenant-a']);
        self::assertFalse($scoped->matchesScope([]));
    }

    public function test_scoped_assignment_matches_only_its_own_scope_values(): void
    {
        $scoped = $this->userRole(['tenant_id' => 'tenant-a']);
        self::assertTrue($scoped->matchesScope(['tenant_id' => 'tenant-a']));
        self::assertFalse($scoped->matchesScope(['tenant_id' => 'tenant-b']));
        self::assertFalse($scoped->matchesScope(['other' => 'tenant-a']));
    }

    public function test_extra_request_keys_the_assignment_does_not_constrain_are_irrelevant(): void
    {
        $scoped = $this->userRole(['tenant_id' => 'tenant-a']);
        self::assertTrue($scoped->matchesScope(['tenant_id' => 'tenant-a', 'department' => 'sales']));
    }

    public function test_every_declared_constraint_must_be_satisfied(): void
    {
        $scoped = $this->userRole(['tenant_id' => 'tenant-a', 'department' => 'sales']);
        self::assertFalse($scoped->matchesScope(['tenant_id' => 'tenant-a']));
        self::assertTrue(
            $scoped->matchesScope(['tenant_id' => 'tenant-a', 'department' => 'sales'])
        );
    }
}
