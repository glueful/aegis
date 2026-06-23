<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for `POST /rbac/users/{user_uuid}/check-role`
 * ({@see \Glueful\Extensions\Aegis\Controllers\UserRoleController::checkUserRole()}).
 */
final class CheckUserRoleData implements RequestData
{
    /** @param array<string,mixed> $scope */
    public function __construct(
        #[Rule('required|string')]
        public readonly string $role_slug,
        #[Rule('array')]
        public readonly array $scope = [],
    ) {
    }
}
