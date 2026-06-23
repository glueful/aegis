<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\ArrayOf;
use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for `POST /rbac/permissions/batch-revoke`
 * ({@see \Glueful\Extensions\Aegis\Controllers\PermissionController::batchRevoke()}).
 */
final class BatchRevokePermissionsData implements RequestData
{
    /** @param list<string> $permission_slugs */
    public function __construct(
        #[Rule('required|string')]
        public readonly string $user_uuid,
        #[ArrayOf('string')]
        #[Rule('required|array')]
        public readonly array $permission_slugs = [],
    ) {
    }
}
