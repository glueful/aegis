<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\DTOs;

use Glueful\Validation\Attributes\Rule;
use Glueful\Validation\Contracts\RequestData;

/**
 * Request body for `PUT /rbac/permissions/{uuid}`
 * ({@see \Glueful\Extensions\Aegis\Controllers\PermissionController::update()}). All optional.
 */
final class UpdatePermissionData implements RequestData
{
    /** @param array<string,mixed>|null $metadata */
    public function __construct(
        #[Rule('string')]
        public readonly ?string $name = null,
        #[Rule('string')]
        public readonly ?string $description = null,
        #[Rule('string')]
        public readonly ?string $category = null,
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
                'description' => $this->description,
                'category' => $this->category,
                'metadata' => $this->metadata,
            ],
            static fn($v): bool => $v !== null,
        );
    }
}
