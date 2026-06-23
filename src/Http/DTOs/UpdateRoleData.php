<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for `PUT /rbac/roles/{uuid}`
 * ({@see \Glueful\Extensions\Aegis\Controllers\RoleController::update()}). All fields optional;
 * only the supplied ones are changed.
 */
final class UpdateRoleData implements RequestData
{
    /** @param array<string,mixed>|null $metadata */
    public function __construct(
        #[Rule('string')]
        public readonly ?string $name = null,
        #[Rule('string')]
        public readonly ?string $description = null,
        #[Rule('string')]
        public readonly ?string $parent_uuid = null,
        #[Rule('string')]
        public readonly ?string $status = null,
        #[Rule('array')]
        public readonly ?array $metadata = null,
    ) {
    }

    /**
     * Only the explicitly-supplied (non-null) fields, so unset fields are left unchanged.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return array_filter(
            [
                'name' => $this->name,
                'description' => $this->description,
                'parent_uuid' => $this->parent_uuid,
                'status' => $this->status,
                'metadata' => $this->metadata,
            ],
            static fn($v): bool => $v !== null,
        );
    }
}
