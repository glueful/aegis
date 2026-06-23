<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\ArrayOf;
use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for assigning/replacing a user's roles
 * (`POST`/`PUT /rbac/users/{user_uuid}/roles`). `POST` (assign) requires a non-empty set —
 * enforced in the controller; `PUT` (replace) accepts an empty array to clear all roles.
 */
final class UserRolesData implements RequestData
{
    /**
     * @param list<string>        $role_uuids
     * @param array<string,mixed> $scope
     */
    public function __construct(
        #[ArrayOf('string')]
        #[Rule('array')]
        public readonly array $role_uuids = [],
        #[Rule('array')]
        public readonly array $scope = [],
        #[Rule('string')]
        public readonly ?string $expires_at = null,
    ) {
    }
}
