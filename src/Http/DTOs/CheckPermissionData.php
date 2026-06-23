<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for `POST /rbac/check-permission`
 * ({@see \Glueful\Extensions\Aegis\Controllers\PermissionController::checkPermission()}).
 */
final class CheckPermissionData implements RequestData
{
    /** @param array<string,mixed> $context */
    public function __construct(
        #[Rule('required|string')]
        public readonly string $user_uuid,
        #[Rule('required|string')]
        public readonly string $permission,
        #[Rule('string')]
        public readonly string $resource = '*',
        #[Rule('array')]
        public readonly array $context = [],
    ) {
    }
}
