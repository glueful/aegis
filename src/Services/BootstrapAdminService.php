<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Services;

use Glueful\Auth\Contracts\UserProviderInterface;
use Glueful\Extensions\Aegis\AegisPermissionProvider;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RolePermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;

/**
 * First-admin bootstrap: resolve a user, create/reuse a role, additively grant the requested
 * permissions to it, and assign the role to the user. The catalog must already be synced (the
 * command does that) so the requested permissions exist; this service validates and fails loudly
 * if any do not.
 *
 * Default grant is `users.read` — enough to unlock GET /users and GET /users/{uuid} — deliberately
 * NOT "all permissions", so the command can't accidentally mint a super-admin. Use `--all-catalog`
 * (→ resolvePermissions) for that.
 *
 * Collaborators are injected so the orchestration is testable against the SQLite harness with a
 * fake UserProvider; the user is resolved through the core seam so Aegis never depends on
 * glueful/users.
 */
final class BootstrapAdminService
{
    public function __construct(
        private readonly UserProviderInterface $users,
        private readonly RoleRepository $roles,
        private readonly PermissionRepository $permissions,
        private readonly RolePermissionRepository $rolePermissions,
        private readonly AegisPermissionProvider $provider,
    ) {
    }

    /**
     * Resolve the effective permission slugs to grant.
     *
     * - `--all-catalog` → every synced catalog slug.
     * - else explicit `--permission` values if any, otherwise the default `users.read`.
     *
     * @param list<string> $explicit     repeated --permission values
     * @param list<string> $catalogSlugs all synced catalog permission slugs
     * @return list<string>
     */
    public static function resolvePermissions(array $explicit, bool $allCatalog, array $catalogSlugs): array
    {
        $slugs = $allCatalog
            ? $catalogSlugs
            : ($explicit !== [] ? $explicit : ['users.read']);

        return array_values(array_unique($slugs));
    }

    /**
     * @param list<string> $permissions effective slugs to grant (already resolved; must exist)
     * @throws \RuntimeException when the user can't be resolved, a permission is unknown, or
     *                           role create/assign fails
     */
    public function bootstrap(string $userIdentifier, string $roleSlug, array $permissions, bool $dryRun): BootstrapAdminResult
    {
        $user = $this->users->findByUuid($userIdentifier) ?? $this->users->findByLogin($userIdentifier);
        if ($user === null) {
            throw new \RuntimeException("User not found: {$userIdentifier}");
        }

        $missing = [];
        foreach ($permissions as $slug) {
            if ($this->permissions->findPermissionBySlug($slug) === null) {
                $missing[] = $slug;
            }
        }
        if ($missing !== []) {
            throw new \RuntimeException('Unknown permission(s) after catalog sync: ' . implode(', ', $missing));
        }

        $role = $this->roles->findRoleBySlug($roleSlug);
        $roleCreated = $role === null;

        if ($dryRun) {
            return new BootstrapAdminResult($user->uuid(), $roleSlug, $roleCreated, $permissions, $permissions, true);
        }

        if ($role === null) {
            $role = $this->roles->createRole([
                'name' => ucfirst($roleSlug),
                'slug' => $roleSlug,
                'description' => 'Bootstrap admin role (managed by glueful/aegis)',
                'level' => 0,
                'is_system' => false,
                'managed_by' => 'glueful/aegis',
                'status' => 'active',
            ]);
            if ($role === null) {
                throw new \RuntimeException("Failed to create role: {$roleSlug}");
            }
        }

        $granted = [];
        foreach ($permissions as $slug) {
            $permission = $this->permissions->findPermissionBySlug($slug);
            if ($permission === null) {
                continue; // validated above; defensive
            }
            // Additive: assignPermissionToRole is itself idempotent, but skip-if-present keeps the
            // reported "granted" list accurate (newly attached only).
            if (!$this->rolePermissions->roleHasPermission($role->getUuid(), $permission->getUuid())) {
                $this->rolePermissions->assignPermissionToRole($role->getUuid(), $permission->getUuid());
                $granted[] = $slug;
            }
        }

        // The grants above wrote role_permissions directly — cached
        // role_permission:* decisions (30 min TTL) must not outlive them.
        if ($granted !== []) {
            $this->provider->invalidateAllCache();
        }

        if (!$this->provider->assignRole($user->uuid(), $roleSlug)) {
            throw new \RuntimeException("Failed to assign role '{$roleSlug}' to user {$user->uuid()}");
        }

        return new BootstrapAdminResult($user->uuid(), $roleSlug, $roleCreated, $granted, $permissions, false);
    }
}
