<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for `POST /rbac/permissions/{uuid}/assign`
 * ({@see \Glueful\Extensions\Aegis\Controllers\PermissionController::assignToUser()}). The grantor
 * is taken from the authenticated identity, never the body.
 */
final class AssignPermissionToUserData implements RequestData
{
    /** @param array<string,mixed>|null $constraints */
    public function __construct(
        #[Rule('required|string')]
        public readonly string $user_uuid,
        #[Rule('string')]
        public readonly string $resource = '*',
        #[Rule('string')]
        public readonly ?string $expires_at = null,
        #[Rule('array')]
        public readonly ?array $constraints = null,
    ) {
    }
}
