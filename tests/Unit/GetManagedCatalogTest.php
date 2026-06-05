<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;

final class GetManagedCatalogTest extends AegisTestCase
{
    public function test_returns_only_managed_rows(): void
    {
        $this->seedPermission(['slug' => 'blog.publish', 'name' => 'Publish', 'managed_by' => 'vendor/blog']);
        $this->seedPermission(['slug' => 'adhoc.thing', 'name' => 'Adhoc', 'managed_by' => null]);

        $managed = $this->makeProvider()->getManagedCatalog();

        self::assertSame(['blog.publish' => 'vendor/blog'], $managed);
        self::assertArrayNotHasKey('adhoc.thing', $managed);
    }
}
