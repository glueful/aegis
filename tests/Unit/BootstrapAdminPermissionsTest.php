<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\Services\BootstrapAdminService;
use PHPUnit\Framework\TestCase;

/**
 * Pure tests for permission resolution — the security-critical "default users.read, not all".
 */
final class BootstrapAdminPermissionsTest extends TestCase
{
    /** @var list<string> */
    private array $catalog = ['users.read', 'users.write', 'posts.read', 'posts.write'];

    public function test_defaults_to_users_read_only(): void
    {
        self::assertSame(['users.read'], BootstrapAdminService::resolvePermissions([], false, $this->catalog));
    }

    public function test_explicit_permissions_replace_the_default(): void
    {
        self::assertSame(
            ['posts.read', 'posts.write'],
            BootstrapAdminService::resolvePermissions(['posts.read', 'posts.write'], false, $this->catalog)
        );
    }

    public function test_all_catalog_grants_every_synced_slug(): void
    {
        self::assertSame($this->catalog, BootstrapAdminService::resolvePermissions([], true, $this->catalog));
    }

    public function test_all_catalog_overrides_explicit(): void
    {
        self::assertSame(
            $this->catalog,
            BootstrapAdminService::resolvePermissions(['users.read'], true, $this->catalog)
        );
    }

    public function test_duplicates_are_collapsed(): void
    {
        self::assertSame(
            ['users.read', 'posts.read'],
            BootstrapAdminService::resolvePermissions(['users.read', 'posts.read', 'users.read'], false, $this->catalog)
        );
    }
}
