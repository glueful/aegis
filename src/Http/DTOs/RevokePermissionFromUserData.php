<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for `DELETE /rbac/permissions/{uuid}/revoke`
 * ({@see \Glueful\Extensions\Aegis\Controllers\PermissionController::revokeFromUser()}).
 */
final class RevokePermissionFromUserData implements RequestData
{
    public function __construct(
        #[Rule('required|string')]
        public readonly string $user_uuid,
    ) {
    }
}
