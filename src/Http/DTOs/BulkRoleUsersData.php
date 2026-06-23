<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\ArrayOf;
use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for bulk-assigning/revoking a role across users
 * (`POST /rbac/roles/{role_uuid}/assign-users`, `DELETE /rbac/roles/{role_uuid}/revoke-users`).
 * A non-empty `user_uuids` is enforced in the controller.
 */
final class BulkRoleUsersData implements RequestData
{
    /**
     * @param list<string>        $user_uuids
     * @param array<string,mixed> $scope
     */
    public function __construct(
        #[ArrayOf('string')]
        #[Rule('array')]
        public readonly array $user_uuids = [],
        #[Rule('array')]
        public readonly array $scope = [],
        #[Rule('string')]
        public readonly ?string $expires_at = null,
    ) {
    }
}
