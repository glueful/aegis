<?php

namespace Glueful\Extensions\Aegis\Database\Migrations;

use Glueful\Database\Migrations\MigrationInterface;
use Glueful\Database\Schema\Interfaces\SchemaBuilderInterface;

/**
 * Rewords the seeded `user` role so it describes what the role is rather than what it grants.
 *
 * 003_SeedDefaultRoles is already applied everywhere, so its text stays as shipped (editing it
 * would change the migration checksum); this follow-up updates the row in place. Only a row that
 * still carries the original seed wording is touched, so an operator's own description survives.
 */
class UpdateDefaultRoleDescriptions implements MigrationInterface
{
    private const DESCRIPTIONS = [
        'user' => [
            'from' => 'Standard user with basic access',
            'to' => 'An individual with an account on the platform.',
        ],
    ];

    public function up(SchemaBuilderInterface $schema): void
    {
        $this->swap($schema, 'from', 'to');
    }

    public function down(SchemaBuilderInterface $schema): void
    {
        $this->swap($schema, 'to', 'from');
    }

    public function getDescription(): string
    {
        return 'Rewords the seeded user role description.';
    }

    private function swap(SchemaBuilderInterface $schema, string $current, string $next): void
    {
        $db = $schema->getConnection();
        foreach (self::DESCRIPTIONS as $slug => $text) {
            $db->table('roles')
                ->where('slug', '=', $slug)
                ->where('description', '=', $text[$current])
                ->update(['description' => $text[$next]]);
        }
    }
}
