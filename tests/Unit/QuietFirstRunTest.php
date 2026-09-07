<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\Services\AegisServiceProvider;
use PHPUnit\Framework\TestCase;

/**
 * "RBAC tables not found" is a real warning on an installed host (permission checks
 * default-deny until migrate:run). On a checkout that has never been installed — no security
 * keys in .env yet — it is the expected state before `php glueful install`/provision creates
 * those tables, and printing it on every first-run command reads as a failure. Framework
 * >= 1.82 exposes `InstallState::isInstalled()` for exactly this distinction.
 */
final class QuietFirstRunTest extends TestCase
{
    private string $base;

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir() . '/aegis-first-run-' . uniqid('', true);
        mkdir($this->base, 0755, true);
    }

    protected function tearDown(): void
    {
        @unlink($this->base . '/.env');
        @rmdir($this->base);
    }

    public function testNoWarningWhileFirstRunIsPending(): void
    {
        self::assertFalse(AegisServiceProvider::shouldWarnAboutMissingRbacTables($this->base), 'no .env');

        file_put_contents($this->base . '/.env', "APP_KEY=\nJWT_KEY=\nTOKEN_SALT=\n");
        self::assertFalse(AegisServiceProvider::shouldWarnAboutMissingRbacTables($this->base), 'keys empty');
    }

    public function testWarningOnceInstalled(): void
    {
        file_put_contents($this->base . '/.env', "APP_KEY=a\nJWT_KEY=b\nTOKEN_SALT=c\n");

        self::assertTrue(AegisServiceProvider::shouldWarnAboutMissingRbacTables($this->base));
    }
}
