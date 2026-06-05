<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\Console\BootstrapAdminCommand;
use PHPUnit\Framework\TestCase;

/**
 * Locks the CLI option wiring (no app boot needed). Guards against the classic
 * InputOption misconfiguration where a repeatable option isn't flagged VALUE_IS_ARRAY.
 */
final class BootstrapAdminCommandConfigTest extends TestCase
{
    public function test_command_name_and_option_contract(): void
    {
        $def = (new BootstrapAdminCommand())->getDefinition();

        self::assertSame('aegis:bootstrap-admin', (new BootstrapAdminCommand())->getName());

        self::assertTrue($def->getOption('user')->isValueRequired());
        self::assertSame('admin', $def->getOption('role')->getDefault());
        self::assertTrue($def->getOption('permission')->isArray(), 'permission is repeatable');
        self::assertSame([], $def->getOption('permission')->getDefault());
        self::assertFalse($def->getOption('all-catalog')->acceptValue(), 'all-catalog is a flag');
        self::assertFalse($def->getOption('dry-run')->acceptValue(), 'dry-run is a flag');
        self::assertFalse($def->getOption('yes')->acceptValue(), 'yes is a flag');
    }
}
