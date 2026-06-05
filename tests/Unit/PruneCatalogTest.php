<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;

final class PruneCatalogTest extends AegisTestCase
{
    public function test_prunes_only_managed_permission_slugs(): void
    {
        $this->seedPermission(['slug' => 'blog.stale', 'name' => 'Stale', 'managed_by' => 'vendor/blog']);
        $this->seedPermission(['slug' => 'adhoc.keep', 'name' => 'Adhoc', 'managed_by' => null]);

        // Even if asked to prune a hand-created slug, it must not be deleted.
        $removed = $this->makeProvider()->pruneCatalog(['blog.stale', 'adhoc.keep']);

        self::assertSame(1, $removed);
        self::assertFalse($this->permissionExists('blog.stale'));
        self::assertTrue($this->permissionExists('adhoc.keep'));
    }

    public function test_get_managed_roles_excludes_hand_created(): void
    {
        $this->seedRole(['slug' => 'blog.editor', 'name' => 'Editor', 'managed_by' => 'vendor/blog']);
        $this->seedRole(['slug' => 'adhoc.role', 'name' => 'Adhoc', 'managed_by' => null]);

        self::assertSame(['blog.editor' => 'vendor/blog'], $this->makeProvider()->getManagedRoles());
    }

    public function test_prunes_only_managed_role_slugs(): void
    {
        $this->seedRole(['slug' => 'blog.staleRole', 'name' => 'Stale', 'managed_by' => 'vendor/blog']);
        $this->seedRole(['slug' => 'adhoc.role', 'name' => 'Adhoc', 'managed_by' => null]);

        $removed = $this->makeProvider()->pruneRoles(['blog.staleRole', 'adhoc.role']);

        self::assertSame(1, $removed);
        self::assertFalse($this->roleExists('blog.staleRole'));
        self::assertTrue($this->roleExists('adhoc.role'));
    }
}
