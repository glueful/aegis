<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for `POST /rbac/roles/{uuid}/assign`
 * ({@see \Glueful\Extensions\Aegis\Controllers\RoleController::assignToUser()}). The actor
 * (`assigned_by`) is taken from the authenticated identity, never the body.
 */
final class AssignRoleToUserData implements RequestData
{
    /** @param array<string,mixed> $scope */
    public function __construct(
        #[Rule('required|string')]
        public readonly string $user_uuid,
        #[Rule('array')]
        public readonly array $scope = [],
        #[Rule('string')]
        public readonly ?string $expires_at = null,
    ) {
    }
}
