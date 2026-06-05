<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;

final class SyncCatalogTest extends AegisTestCase
{
    /** @return array<string, string|null> */
    private function perm(string $slug, string $managedBy = 'vendor/blog', ?string $category = 'blog'): array
    {
        return [
            'slug' => $slug, 'name' => ucfirst($slug), 'description' => null,
            'category' => $category, 'resource_type' => null, 'managed_by' => $managedBy,
        ];
    }

    public function test_creates_then_is_idempotent(): void
    {
        $provider = $this->makeProvider();
        $permissions = [$this->perm('blog.publish')];

        $first = $provider->syncCatalog($permissions, []);
        self::assertSame(1, $first->created);

        $second = $provider->syncCatalog($permissions, []);
        self::assertSame(0, $second->created);
        self::assertSame(1, $second->unchanged);
    }

    public function test_detects_stale_managed_rows_only(): void
    {
        $this->seedPermission(['slug' => 'blog.old', 'name' => 'Old', 'managed_by' => 'vendor/blog']);
        $this->seedPermission(['slug' => 'adhoc.keep', 'name' => 'Adhoc', 'managed_by' => null]);

        $result = $this->makeProvider()->syncCatalog([$this->perm('blog.new')], []);

        self::assertContains('blog.old', $result->stale);
        self::assertNotContains('adhoc.keep', $result->stale, 'hand-created rows are never stale');
    }

    public function test_claims_existing_unmanaged_row_with_matching_slug(): void
    {
        // Existing hand-created row (managed_by NULL) with the same slug must become managed.
        $this->seedPermission(['slug' => 'blog.publish', 'name' => 'Publish', 'managed_by' => null]);

        $provider = $this->makeProvider();
        self::assertArrayNotHasKey('blog.publish', $provider->getManagedCatalog());

        $result = $provider->syncCatalog([$this->perm('blog.publish')], []);

        self::assertSame(1, $result->updated, 'claiming an unmanaged row counts as an update');
        self::assertSame('vendor/blog', $provider->getManagedCatalog()['blog.publish'] ?? null);
    }

    public function test_role_grants_added_without_duplicates(): void
    {
        $provider = $this->makeProvider();
        $permissions = [$this->perm('blog.publish'), $this->perm('blog.delete')];

        // First sync: role grants [blog.publish].
        $provider->syncCatalog($permissions, [[
            'slug' => 'blog.editor', 'name' => 'Editor', 'description' => null,
            'level' => 40, 'parent' => null, 'grants' => ['blog.publish'], 'managed_by' => 'vendor/blog',
        ]]);
        self::assertSame(['blog.publish'], $this->roleGrantSlugs('blog.editor'));

        // Second sync: role now grants [blog.publish, blog.delete] — adds the missing one, no dupes.
        $provider->syncCatalog($permissions, [[
            'slug' => 'blog.editor', 'name' => 'Editor', 'description' => null,
            'level' => 40, 'parent' => null, 'grants' => ['blog.publish', 'blog.delete'], 'managed_by' => 'vendor/blog',
        ]]);

        $grants = $this->roleGrantSlugs('blog.editor');
        sort($grants);
        self::assertSame(['blog.delete', 'blog.publish'], $grants);
    }
}
