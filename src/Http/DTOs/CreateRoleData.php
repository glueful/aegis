<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for `POST /rbac/roles` ({@see \Glueful\Extensions\Aegis\Controllers\RoleController::create()}).
 *
 * Structural validation (required name/slug, field types) runs here via the hydrated DTO; the
 * duplicate name/slug and parent-cycle checks stay in {@see \Glueful\Extensions\Aegis\Services\RoleService}.
 */
final class CreateRoleData implements RequestData
{
    /** @param array<string,mixed>|null $metadata */
    public function __construct(
        #[Rule('required|string')]
        public readonly string $name,
        #[Rule('required|string')]
        public readonly string $slug,
        #[Rule('string')]
        public readonly ?string $description = null,
        #[Rule('string')]
        public readonly ?string $parent_uuid = null,
        #[Rule('numeric')]
        public readonly ?int $level = null,
        #[Rule('string')]
        public readonly ?string $status = null,
        #[Rule('array')]
        public readonly ?array $metadata = null,
    ) {
    }

    /**
     * The non-null fields as the array {@see RoleService::createRole()} consumes.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return array_filter(
            [
                'name' => $this->name,
                'slug' => $this->slug,
                'description' => $this->description,
                'parent_uuid' => $this->parent_uuid,
                'level' => $this->level,
                'status' => $this->status,
                'metadata' => $this->metadata,
            ],
            static fn($v): bool => $v !== null,
        );
    }
}
