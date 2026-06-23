<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\ArrayOf;
use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for the role↔permission endpoints
 * (`POST`/`PUT /rbac/roles/{uuid}/permissions`). `POST` (assign) requires a non-empty set —
 * enforced in the controller; `PUT` (replace) accepts an empty array to clear all grants.
 */
final class RolePermissionsData implements RequestData
{
    /** @param list<string> $permission_uuids */
    public function __construct(
        #[ArrayOf('string')]
        #[Rule('array')]
        public readonly array $permission_uuids = [],
    ) {
    }
}
