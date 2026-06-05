<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Auth\UserIdentity;
use Glueful\Extensions\Aegis\IdentityClaimsProvider;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;
use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;
use Glueful\Helpers\Utils;

final class IdentityClaimsProviderTest extends AegisTestCase
{
    private function provider(): IdentityClaimsProvider
    {
        // Shared connection is already set by AegisTestCase::setUp().
        return new IdentityClaimsProvider(new UserRoleRepository($this->connection));
    }

    private function createUserRolesTable(): void
    {
        $this->connection->getPDO()->exec('CREATE TABLE user_roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT, user_uuid TEXT, role_uuid TEXT, scope TEXT,
            granted_by TEXT, expires_at TEXT, created_at TEXT
        )');
    }

    private function assign(string $userUuid, string $roleUuid): void
    {
        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO user_roles (uuid, user_uuid, role_uuid, created_at) VALUES (?,?,?,?)'
        );
        $stmt->execute([Utils::generateNanoID(), $userUuid, $roleUuid, date('Y-m-d H:i:s')]);
    }

    public function test_enrich_adds_role_claims_for_assigned_user(): void
    {
        $this->createUserRolesTable();
        $roleUuid = Utils::generateNanoID();
        $this->seedRole(['uuid' => $roleUuid, 'slug' => 'editor']);
        $this->assign('u1', $roleUuid);

        $out = $this->provider()->enrich(new UserIdentity('u1', status: 'active'));
        self::assertContains('editor', $out->roles());

        // An unassigned principal gets no fabricated roles.
        $none = $this->provider()->enrich(new UserIdentity('nobody'));
        self::assertSame([], $none->roles());
    }

    public function test_enrich_is_additive_and_deduplicated(): void
    {
        $this->createUserRolesTable();
        $roleUuid = Utils::generateNanoID();
        $this->seedRole(['uuid' => $roleUuid, 'slug' => 'editor']);
        $this->assign('u2', $roleUuid);

        // Identity already carries 'editor' + 'viewer'; enrichment unions, no duplicates.
        $identity = (new UserIdentity('u2', status: 'active'))->withClaims(['roles' => ['viewer', 'editor']]);
        $out = $this->provider()->enrich($identity);

        $roles = $out->roles();
        self::assertContains('editor', $roles);
        self::assertContains('viewer', $roles);
        self::assertSame(count($roles), count(array_unique($roles)), 'roles must be deduplicated');
    }

    public function test_expired_assignments_are_ignored(): void
    {
        $this->createUserRolesTable();
        $roleUuid = Utils::generateNanoID();
        $this->seedRole(['uuid' => $roleUuid, 'slug' => 'editor']);

        // Assign with a past expiry — must not surface as an active role.
        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO user_roles (uuid, user_uuid, role_uuid, expires_at, created_at) VALUES (?,?,?,?,?)'
        );
        $stmt->execute([
            Utils::generateNanoID(), 'u3', $roleUuid,
            date('Y-m-d H:i:s', time() - 3600), date('Y-m-d H:i:s'),
        ]);

        $out = $this->provider()->enrich(new UserIdentity('u3', status: 'active'));
        self::assertSame([], $out->roles());
    }
}
