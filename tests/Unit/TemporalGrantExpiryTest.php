<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Cache\Drivers\ArrayCacheDriver;
use Glueful\Extensions\Aegis\AegisPermissionProvider;
use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;
use Glueful\Helpers\Utils;

final class TemporalGrantExpiryTest extends AegisTestCase
{
    private AegisPermissionProvider $provider;

    protected function setUp(): void
    {
        parent::setUp();
        $this->provider = $this->makeProvider();
        $this->injectCache($this->provider, new ArrayCacheDriver());
    }

    public function test_direct_permission_expires_without_stale_decision_cache(): void
    {
        $this->seedPermission(['uuid' => 'permission-1', 'slug' => 'entries.publish']);
        $this->seedDirectGrant('user-1', 'permission-1', '+1 day');

        self::assertTrue($this->provider->can('user-1', 'entries.publish', '*'));

        $this->expireDirectGrant('user-1', 'permission-1');

        self::assertFalse(
            $this->provider->can('user-1', 'entries.publish', '*'),
            'Direct grants must stop authorizing as soon as expires_at is in the past'
        );
    }

    public function test_scoped_role_assignment_expires_without_stale_role_cache(): void
    {
        $this->seedGrantedRole('entries.edit', 'editor', 'permission-1', 'editor-role');
        $this->seedRoleGrant('user-1', 'editor-role', '+1 day');

        self::assertTrue($this->provider->can('user-1', 'entries.edit', '*'));

        $this->expireRoleGrant('user-1', 'editor-role');

        self::assertFalse(
            $this->provider->can('user-1', 'entries.edit', '*'),
            'Role grants must stop authorizing as soon as expires_at is in the past'
        );
    }

    public function test_role_permission_expiry_is_not_hidden_by_role_permission_cache(): void
    {
        $this->seedGrantedRole('entries.delete', 'editor', 'permission-1', 'editor-role');
        $this->seedRoleGrant('user-1', 'editor-role', null);

        self::assertTrue($this->provider->can('user-1', 'entries.delete', '*'));

        $stmt = $this->connection->getPDO()->prepare(
            'UPDATE role_permissions SET expires_at = ? WHERE role_uuid = ? AND permission_uuid = ?'
        );
        $stmt->execute([$this->dateFromRelative('-1 day'), 'editor-role', 'permission-1']);

        self::assertFalse(
            $this->provider->can('user-1', 'entries.delete', '*'),
            'Role-permission grants must stop authorizing as soon as expires_at is in the past'
        );
    }

    private function seedGrantedRole(
        string $permissionSlug,
        string $roleSlug,
        string $permissionUuid,
        string $roleUuid
    ): void {
        $this->seedPermission(['uuid' => $permissionUuid, 'slug' => $permissionSlug]);
        $this->seedRole(['uuid' => $roleUuid, 'slug' => $roleSlug]);

        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO role_permissions (uuid, role_uuid, permission_uuid, created_at)
             VALUES (?, ?, ?, datetime("now"))'
        );
        $stmt->execute([Utils::generateNanoID(), $roleUuid, $permissionUuid]);
    }

    private function seedDirectGrant(string $userUuid, string $permissionUuid, string $expiresAt): void
    {
        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO user_permissions (uuid, user_uuid, permission_uuid, expires_at, created_at)
             VALUES (?, ?, ?, ?, datetime("now"))'
        );
        $stmt->execute([Utils::generateNanoID(), $userUuid, $permissionUuid, $this->dateFromRelative($expiresAt)]);
    }

    private function expireDirectGrant(string $userUuid, string $permissionUuid): void
    {
        $stmt = $this->connection->getPDO()->prepare(
            'UPDATE user_permissions SET expires_at = ? WHERE user_uuid = ? AND permission_uuid = ?'
        );
        $stmt->execute([$this->dateFromRelative('-1 day'), $userUuid, $permissionUuid]);
    }

    private function seedRoleGrant(string $userUuid, string $roleUuid, ?string $expiresAt): void
    {
        $stmt = $this->connection->getPDO()->prepare(
            'INSERT INTO user_roles (uuid, user_uuid, role_uuid, scope, granted_by, expires_at, created_at)
             VALUES (?, ?, ?, NULL, NULL, ?, datetime("now"))'
        );
        $stmt->execute([
            Utils::generateNanoID(),
            $userUuid,
            $roleUuid,
            $expiresAt === null ? null : $this->dateFromRelative($expiresAt),
        ]);
    }

    private function expireRoleGrant(string $userUuid, string $roleUuid): void
    {
        $stmt = $this->connection->getPDO()->prepare(
            'UPDATE user_roles SET expires_at = ? WHERE user_uuid = ? AND role_uuid = ?'
        );
        $stmt->execute([$this->dateFromRelative('-1 day'), $userUuid, $roleUuid]);
    }

    private function dateFromRelative(string $relative): string
    {
        $timestamp = strtotime($relative);
        self::assertIsInt($timestamp);

        return date('Y-m-d H:i:s', $timestamp);
    }

    /**
     * @param ArrayCacheDriver<mixed> $cache
     */
    private function injectCache(AegisPermissionProvider $provider, ArrayCacheDriver $cache): void
    {
        $ref = new \ReflectionClass($provider);
        foreach (['cache' => $cache, 'cacheEnabled' => true] as $prop => $value) {
            $property = $ref->getProperty($prop);
            $property->setAccessible(true);
            $property->setValue($provider, $value);
        }
    }
}
