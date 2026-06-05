<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Services;

/**
 * Outcome of {@see BootstrapAdminService::bootstrap()} — what was (or, in dry-run, would be) done.
 */
final class BootstrapAdminResult
{
    /**
     * @param list<string> $granted   permission slugs newly attached to the role this run
     * @param list<string> $requested all permission slugs requested (granted ∪ already-present)
     */
    public function __construct(
        public readonly string $userUuid,
        public readonly string $roleSlug,
        public readonly bool $roleCreated,
        public readonly array $granted,
        public readonly array $requested,
        public readonly bool $dryRun,
    ) {
    }
}
