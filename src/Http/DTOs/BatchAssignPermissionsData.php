<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for `POST /rbac/permissions/batch-assign`
 * ({@see \Glueful\Extensions\Aegis\Controllers\PermissionController::batchAssign()}).
 */
final class BatchAssignPermissionsData implements RequestData
{
    /**
     * @param list<array<string,mixed>> $permissions  Each: {permission, resource, options}.
     * @param array<string,mixed>       $options       Shared options merged into each grant.
     */
    public function __construct(
        #[Rule('required|string')]
        public readonly string $user_uuid,
        #[Rule('required|array')]
        public readonly array $permissions = [],
        #[Rule('array')]
        public readonly array $options = [],
    ) {
    }
}
