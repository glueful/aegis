<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Guardrail: catalog sync is migration-like and CLI-only. boot() must never sync, or normal
 * web/CLI requests would mutate permission tables.
 */
final class NoBootSyncTest extends TestCase
{
    public function test_boot_does_not_call_sync_catalog(): void
    {
        $src = file_get_contents(dirname(__DIR__, 2) . '/src/Services/AegisServiceProvider.php');
        self::assertNotFalse($src);

        $start = strpos($src, 'function boot(');
        self::assertNotFalse($start, 'boot() method should exist');

        $bootBody = substr($src, $start, 4000);
        self::assertStringNotContainsString('syncCatalog', $bootBody, 'boot() must not sync; sync is CLI-only');
    }
}
