<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Extensions\Aegis\Repositories\RolePermissionRepository;
use Glueful\Extensions\Aegis\Tests\Support\AegisTestCase;

/**
 * A stored resource_filter is interpolated into a regex for wildcard matching. It must be
 * preg_quote'd so its metacharacters are literal -- only `*` acts as a wildcard -- so a
 * malformed or hostile stored filter cannot become an arbitrary (ReDoS-prone) pattern.
 */
final class ResourceFilterMatchingTest extends AegisTestCase
{
    /**
     * @param array<string, mixed> $filter
     */
    private function filterMatches(array $filter, string $resource): bool
    {
        $repo = new RolePermissionRepository($this->connection);
        $method = new \ReflectionMethod($repo, 'matchesResourceFilter');
        $method->setAccessible(true);

        /** @var bool $result */
        $result = $method->invoke($repo, $filter, $resource);
        return $result;
    }

    public function test_wildcard_matches_prefix(): void
    {
        self::assertTrue($this->filterMatches(['resource' => 'users.*'], 'users.create'));
    }

    public function test_dot_is_literal_not_a_regex_wildcard(): void
    {
        // `users.*` must require a literal dot -- it must not match `usersXcreate`.
        self::assertFalse($this->filterMatches(['resource' => 'users.*'], 'usersXcreate'));
    }

    public function test_regex_metacharacters_in_filter_are_literal(): void
    {
        // A hostile/malformed stored filter cannot become an arbitrary regex.
        self::assertFalse($this->filterMatches(['resource' => '(a+)+$'], 'aaaa'));
    }

    public function test_empty_or_star_matches_all(): void
    {
        self::assertTrue($this->filterMatches(['resource' => '*'], 'anything'));
        self::assertTrue($this->filterMatches([], 'anything'));
    }
}
