<?php

namespace Glueful\Extensions\Aegis\Models;

/**
 * Permission Model
 *
 * Represents a permission in the RBAC system
 *
 * Features:
 * - Permission categorization
 * - Resource type classification
 * - System permission protection
 * - Metadata support for flexible permissions
 */
class Permission implements \JsonSerializable
{
    private string $uuid;
    private string $name;
    private string $slug;
    private ?string $description;
    private ?string $category;
    private ?string $resourceType;
    private bool $isSystem;
    private ?string $managedBy;
    /** @var array<string, mixed> */
    private array $metadata;
    private string $createdAt;

    /**
     * @param array<string, mixed> $data
     */
    public function __construct(array $data = [])
    {
        $this->uuid = $data['uuid'] ?? '';
        $this->name = $data['name'] ?? '';
        $this->slug = $data['slug'] ?? '';
        $this->description = $data['description'] ?? null;
        $this->category = $data['category'] ?? null;
        $this->resourceType = $data['resource_type'] ?? null;
        $this->isSystem = (bool)($data['is_system'] ?? false);
        $this->managedBy = $data['managed_by'] ?? null;
        $this->metadata = isset($data['metadata']) ? json_decode($data['metadata'], true) ?? [] : [];
        $this->createdAt = $data['created_at'] ?? '';
    }

    public function getManagedBy(): ?string
    {
        return $this->managedBy;
    }

    public function getUuid(): string
    {
        return $this->uuid;
    }

    public function setUuid(string $uuid): self
    {
        $this->uuid = $uuid;
        return $this;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): self
    {
        $this->name = $name;
        return $this;
    }

    public function getSlug(): string
    {
        return $this->slug;
    }

    public function setSlug(string $slug): self
    {
        $this->slug = $slug;
        return $this;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function setDescription(?string $description): self
    {
        $this->description = $description;
        return $this;
    }

    public function getCategory(): ?string
    {
        return $this->category;
    }

    public function setCategory(?string $category): self
    {
        $this->category = $category;
        return $this;
    }

    public function getResourceType(): ?string
    {
        return $this->resourceType;
    }

    public function setResourceType(?string $resourceType): self
    {
        $this->resourceType = $resourceType;
        return $this;
    }

    public function isSystem(): bool
    {
        return $this->isSystem;
    }

    public function setIsSystem(bool $isSystem): self
    {
        $this->isSystem = $isSystem;
        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function getMetadata(): array
    {
        return $this->metadata;
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function setMetadata(array $metadata): self
    {
        $this->metadata = $metadata;
        return $this;
    }

    public function getMetadataValue(string $key, mixed $default = null): mixed
    {
        return $this->metadata[$key] ?? $default;
    }

    public function setMetadataValue(string $key, mixed $value): self
    {
        $this->metadata[$key] = $value;
        return $this;
    }

    public function getCreatedAt(): string
    {
        return $this->createdAt;
    }

    public function hasCategory(): bool
    {
        return $this->category !== null;
    }

    public function hasResourceType(): bool
    {
        return $this->resourceType !== null;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'uuid' => $this->uuid,
            'name' => $this->name,
            'slug' => $this->slug,
            'description' => $this->description,
            'category' => $this->category,
            'resource_type' => $this->resourceType,
            'is_system' => $this->isSystem,
            'metadata' => json_encode($this->metadata),
            'created_at' => $this->createdAt
        ];
    }

    /**
     * Serialize for JSON responses. Without this, the model's private properties encode to an empty
     * object (`{}`), so endpoints returning Permission objects (e.g. a user's direct permissions)
     * would carry no slug/uuid for clients to read.
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * @return array<string, mixed>
     */
    public function toArrayForInsert(): array
    {
        return array_filter($this->toArray(), fn($value) => $value !== null);
    }

    public function __toString(): string
    {
        return $this->name;
    }
}
