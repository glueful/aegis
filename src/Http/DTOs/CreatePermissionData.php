<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for `POST /rbac/permissions`
 * ({@see \Glueful\Extensions\Aegis\Controllers\PermissionController::create()}).
 */
final class CreatePermissionData implements RequestData
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
        public readonly ?string $category = null,
        #[Rule('string')]
        public readonly ?string $resource_type = null,
        #[Rule('array')]
        public readonly ?array $metadata = null,
    ) {
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return array_filter(
            [
                'name' => $this->name,
                'slug' => $this->slug,
                'description' => $this->description,
                'category' => $this->category,
                'resource_type' => $this->resource_type,
                'metadata' => $this->metadata,
            ],
            static fn($v): bool => $v !== null,
        );
    }
}
