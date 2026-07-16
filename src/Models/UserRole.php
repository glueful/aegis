<?php

namespace Glueful\Extensions\Aegis\Models;

/**
 * User Role Assignment Model
 *
 * Represents the assignment of a role to a user
 *
 * Features:
 * - Scoped role assignments (tenant, department, etc.)
 * - Temporal permissions (expiry support)
 * - Assignment tracking (who granted the role)
 * - Audit trail support
 */
class UserRole
{
    private string $uuid;
    private string $userUuid;
    private string $roleUuid;
    /** @var array<string, mixed>|null */
    private ?array $scope;
    private ?string $grantedBy;
    private ?string $expiresAt;
    private string $createdAt;

    /**
     * @param array<string, mixed> $data
     */
    public function __construct(array $data = [])
    {
        $this->uuid = $data['uuid'] ?? '';
        $this->userUuid = $data['user_uuid'] ?? '';
        $this->roleUuid = $data['role_uuid'] ?? '';
        $this->scope = isset($data['scope']) ? json_decode($data['scope'], true) : null;
        $this->grantedBy = $data['granted_by'] ?? null;
        $this->expiresAt = $data['expires_at'] ?? null;
        $this->createdAt = $data['created_at'] ?? '';
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

    public function getUserUuid(): string
    {
        return $this->userUuid;
    }

    public function setUserUuid(string $userUuid): self
    {
        $this->userUuid = $userUuid;
        return $this;
    }

    public function getRoleUuid(): string
    {
        return $this->roleUuid;
    }

    public function setRoleUuid(string $roleUuid): self
    {
        $this->roleUuid = $roleUuid;
        return $this;
    }

    /**
     * @return array<string, mixed>|null
     */
    public function getScope(): ?array
    {
        return $this->scope;
    }

    /**
     * @param array<string, mixed>|null $scope
     */
    public function setScope(?array $scope): self
    {
        $this->scope = $scope;
        return $this;
    }

    public function getScopeValue(string $key, mixed $default = null): mixed
    {
        return $this->scope[$key] ?? $default;
    }

    public function setScopeValue(string $key, mixed $value): self
    {
        if ($this->scope === null) {
            $this->scope = [];
        }
        $this->scope[$key] = $value;
        return $this;
    }

    public function getGrantedBy(): ?string
    {
        return $this->grantedBy;
    }

    public function setGrantedBy(?string $grantedBy): self
    {
        $this->grantedBy = $grantedBy;
        return $this;
    }

    public function getExpiresAt(): ?string
    {
        return $this->expiresAt;
    }

    public function setExpiresAt(?string $expiresAt): self
    {
        $this->expiresAt = $expiresAt;
        return $this;
    }

    public function getCreatedAt(): string
    {
        return $this->createdAt;
    }

    public function hasScope(): bool
    {
        return $this->scope !== null && !empty($this->scope);
    }

    public function hasExpiry(): bool
    {
        return $this->expiresAt !== null;
    }

    public function isExpired(): bool
    {
        if (!$this->hasExpiry()) {
            return false;
        }
        return strtotime((string) $this->expiresAt) < time();
    }

    public function isActive(): bool
    {
        return !$this->isExpired();
    }

    /**
     * Whether this assignment applies within the given request scope context.
     *
     * FAIL-CLOSED SEMANTICS: an assignment that carries scope (e.g. `{tenant_id: A}`)
     * is a CONSTRAINT — every key it declares must be present and equal in the request
     * context. A request with NO scope context therefore never satisfies a scoped
     * assignment (previously it matched trivially, which let a tenant-scoped role act
     * as global through any caller that omitted scope). The comparison direction is
     * assignment-constraints ⊆ request-context: extra request keys the assignment
     * does not constrain are irrelevant. An UNSCOPED assignment is global and matches
     * any request context, including an empty one.
     *
     * @param array<string, mixed> $requestScope the scope context of the current check
     */
    public function matchesScope(array $requestScope): bool
    {
        $constraints = $this->scope ?? [];
        if ($constraints === []) {
            return true; // No scope restriction means it applies globally
        }

        foreach ($constraints as $key => $value) {
            if (!array_key_exists($key, $requestScope) || $requestScope[$key] !== $value) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'uuid' => $this->uuid,
            'user_uuid' => $this->userUuid,
            'role_uuid' => $this->roleUuid,
            'scope' => $this->scope ? json_encode($this->scope) : null,
            'granted_by' => $this->grantedBy,
            'expires_at' => $this->expiresAt,
            'created_at' => $this->createdAt
        ];
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
        return $this->userUuid . ':' . $this->roleUuid;
    }
}
