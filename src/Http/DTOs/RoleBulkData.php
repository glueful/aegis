<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\ArrayOf;
use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for `POST /rbac/roles/bulk`
 * ({@see \Glueful\Extensions\Aegis\Controllers\RoleController::bulk()}).
 */
final class RoleBulkData implements RequestData
{
    /** @param list<string> $role_ids */
    public function __construct(
        #[Rule('required|string')]
        public readonly string $action,
        #[ArrayOf('string')]
        #[Rule('required|array')]
        public readonly array $role_ids = [],
        #[Rule('boolean')]
        public readonly bool $force = false,
    ) {
    }
}
