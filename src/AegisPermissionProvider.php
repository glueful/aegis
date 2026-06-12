<?php

namespace Glueful\Extensions\Aegis;

use Glueful\Bootstrap\ApplicationContext;
use Glueful\Interfaces\Permission\PermissionProviderInterface;
use Glueful\Interfaces\Permission\PermissionCatalogSyncInterface;
use Glueful\Interfaces\Permission\CatalogPruneInterface;
use Glueful\Interfaces\Permission\RoleCatalogSyncInterface;
use Glueful\Permissions\Catalog\SyncResult;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;
use Glueful\Extensions\Aegis\Repositories\UserPermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RolePermissionRepository;
use Glueful\Extensions\Aegis\Models\Role;
use Glueful\Cache\CacheStore;

/**
 * RBAC Permission Provider
 *
 * Implements role-based access control with hierarchical roles,
 * direct user permissions, and comprehensive permission management.
 *
 * Features:
 * - Hierarchical role system
 * - Direct user permissions (overrides)
 * - Resource-level permission filtering
 * - Temporal permissions (expiry)
 * - Permission inheritance
 * - Scoped permissions
 */
class AegisPermissionProvider implements
    PermissionProviderInterface,
    PermissionCatalogSyncInterface,
    CatalogPruneInterface,
    RoleCatalogSyncInterface
{
    private ApplicationContext $context;
    /** @var CacheStore<mixed>|null */
    private ?CacheStore $cache = null;
    private ?RoleRepository $roleRepository = null;
    private ?PermissionRepository $permissionRepository = null;
    private ?UserRoleRepository $userRoleRepository = null;
    private ?UserPermissionRepository $userPermissionRepository = null;
    private ?RolePermissionRepository $rolePermissionRepository = null;
    /** @var array<string, mixed> */
    private array $config = [
        'cache_ttl' => 3600,
        'cache_enabled' => true,
        'cache_prefix' => 'rbac:',
        'enable_hierarchy' => true,
        'enable_inheritance' => true,
        'max_hierarchy_depth' => 10
    ];
    /** @var array<string, array<string, list<string>>> */
    private array $permissionCache = [];
    /** @var array<string, list<Role>> */
    private array $userRolesCache = [];
    private string $cachePrefix = 'rbac:';
    private bool $cacheEnabled = true;

    
    public function __construct(ApplicationContext $context)
    {
        $this->context = $context;
    }

public function initialize(array $config = []): void
    {
        $this->config = array_merge([
            'cache_ttl' => 3600,
            'cache_enabled' => true,
            'cache_prefix' => 'rbac:',
            'enable_hierarchy' => true,
            'enable_inheritance' => true,
            'max_hierarchy_depth' => 10
        ], $config);

        $this->cacheEnabled = $this->config['cache_enabled'];
        $this->cachePrefix = $this->config['cache_prefix'];

        // Initialize cache store if enabled
        if ($this->cacheEnabled) {
            try {
                $this->cache = container($this->context)->get(CacheStore::class);
            } catch (\Exception $e) {
                // Graceful degradation - disable cache if initialization fails
                $this->cacheEnabled = false;
                $this->cache = null;
                error_log("RBAC Cache initialization failed: " . $e->getMessage());
            }
        }

        // Don't instantiate repositories here - use lazy loading
    }

    /**
     * Get role repository (lazy loading)
     */
    private function getRoleRepository(): RoleRepository
    {
        if ($this->roleRepository === null) {
            $this->roleRepository = new RoleRepository();
        }
        return $this->roleRepository;
    }

    /**
     * Get permission repository (lazy loading)
     */
    private function getPermissionRepository(): PermissionRepository
    {
        if ($this->permissionRepository === null) {
            $this->permissionRepository = new PermissionRepository();
        }
        return $this->permissionRepository;
    }

    /**
     * Get user role repository (lazy loading)
     */
    private function getUserRoleRepository(): UserRoleRepository
    {
        if ($this->userRoleRepository === null) {
            $this->userRoleRepository = new UserRoleRepository();
        }
        return $this->userRoleRepository;
    }

    /**
     * Get user permission repository (lazy loading)
     */
    private function getUserPermissionRepository(): UserPermissionRepository
    {
        if ($this->userPermissionRepository === null) {
            $this->userPermissionRepository = new UserPermissionRepository();
        }
        return $this->userPermissionRepository;
    }

    /**
     * Get role permission repository (lazy loading)
     */
    private function getRolePermissionRepository(): RolePermissionRepository
    {
        if ($this->rolePermissionRepository === null) {
            $this->rolePermissionRepository = new RolePermissionRepository();
        }
        return $this->rolePermissionRepository;
    }

    public function can(string $userUuid, string $permission, string $resource, array $context = []): bool
    {
        // Perform the actual permission check
        if ($this->hasDirectPermission($userUuid, $permission, $resource, $context)) {
            return true;
        }

        return $this->hasRoleBasedPermission($userUuid, $permission, $resource, $context);
    }

    public function getUserPermissions(string $userUuid): array
    {
        // Check memory cache first
        if (isset($this->permissionCache[$userUuid])) {
            return $this->permissionCache[$userUuid];
        }

        // Check distributed cache
        $cacheKey = $this->generateCacheKey('user_permissions', $userUuid);
        if ($this->cacheEnabled && $this->cache !== null) {
            try {
                $cached = $this->cache->get($cacheKey);
                if ($cached !== null) {
                    $this->permissionCache[$userUuid] = $cached;
                    return $cached;
                }
            } catch (\Exception $e) {
                // Log but continue without cache
                error_log("Cache read failed for user permissions {$userUuid}: " . $e->getMessage());
            }
        }

        // Build permissions from scratch
        $permissions = [];

        // Get direct user permissions
        $directPermissions = $this->getDirectUserPermissions($userUuid);
        $permissions = array_merge_recursive($permissions, $directPermissions);

        // Get role-based permissions
        $rolePermissions = $this->getRoleBasedPermissions($userUuid);
        $permissions = array_merge_recursive($permissions, $rolePermissions);

        // Cache the result
        $this->permissionCache[$userUuid] = $permissions;
        if ($this->cacheEnabled && $this->cache !== null) {
            try {
                $this->cache->set($cacheKey, $permissions, (int) $this->config['cache_ttl']);
            } catch (\Exception $e) {
                error_log("Cache write failed for user permissions {$userUuid}: " . $e->getMessage());
            }
        }

        return $permissions;
    }

    public function assignPermission(string $userUuid, string $permission, string $resource, array $options = []): bool
    {
        $permissionModel = $this->getPermissionRepository()->findPermissionBySlug($permission);
        if (!$permissionModel) {
            return false;
        }

        $data = [
            'user_uuid' => $userUuid,
            'permission_uuid' => $permissionModel->getUuid(),
            'granted_by' => $options['granted_by'] ?? null,
            'expires_at' => $options['expires_at'] ?? null
        ];

        // Set resource filter if specified
        if ($resource !== '*') {
            $data['resource_filter'] = json_encode(['resource' => $resource]);
        }

        // Set constraints if specified
        if (isset($options['constraints'])) {
            $data['constraints'] = json_encode($options['constraints']);
        }

        try {
            $result = $this->getUserPermissionRepository()->create($data);
            if (!empty($result)) {
                $this->invalidateUserCache($userUuid);
                return true;
            }
        } catch (\Exception $e) {
            // Log error but don't throw
            error_log("Failed to assign permission: " . $e->getMessage());
        }

        return false;
    }

    public function revokePermission(string $userUuid, string $permission, string $resource): bool
    {
        $permissionModel = $this->getPermissionRepository()->findPermissionBySlug($permission);
        if (!$permissionModel) {
            return false;
        }

        $result = $this->getUserPermissionRepository()->revokeUserPermission($userUuid, $permissionModel->getUuid());

        if ($result) {
            $this->invalidateUserCache($userUuid);
            return true;
        }

        return false;
    }

    public function getAvailablePermissions(): array
    {
        $permissions = $this->getPermissionRepository()->findAllPermissions();
        $result = [];

        foreach ($permissions as $permission) {
            $result[$permission->getSlug()] = $permission->getDescription() ?: $permission->getName();
        }

        return $result;
    }

    /**
     * Persisted, extension/app-managed permissions (managed_by IS NOT NULL) as slug => managed_by.
     * Hand-created rows are excluded — they are never stale/prunable.
     *
     * @return array<string, string>
     */
    public function getManagedCatalog(): array
    {
        return $this->getPermissionRepository()->findManaged();
    }

    /** @param string[] $slugs */
    public function pruneCatalog(array $slugs): int
    {
        $deleted = $this->getPermissionRepository()->deleteManagedBySlugs($slugs);
        if ($deleted > 0) {
            $this->invalidateAllCache();
        }
        return $deleted;
    }

    /** @return array<string, string> */
    public function getManagedRoles(): array
    {
        return $this->getRoleRepository()->findManaged();
    }

    /** @param string[] $roleSlugs */
    public function pruneRoles(array $roleSlugs): int
    {
        $deleted = $this->getRoleRepository()->deleteManagedBySlugs($roleSlugs);
        if ($deleted > 0) {
            $this->invalidateAllCache();
        }
        return $deleted;
    }

    /**
     * @param array<int, array<string, mixed>> $permissions each Permission::toArray()
     * @param array<int, array<string, mixed>> $roles       each Role::toArray()
     */
    public function syncCatalog(array $permissions, array $roles): SyncResult
    {
        $repo = $this->getPermissionRepository();
        $created = 0;
        $updated = 0;
        $unchanged = 0;
        $declaredSlugs = [];
        // Capture slug => uuid as we upsert so syncRoles() does NOT re-query via
        // findPermissionBySlug(), which caches null misses and would return a stale null
        // for a permission created earlier in this same call.
        $slugToUuid = [];

        foreach ($permissions as $perm) {
            $slug = (string) $perm['slug'];
            $declaredSlugs[$slug] = true;
            $existing = $repo->findPermissionBySlug($slug);

            // Update payload carries managed_by so claiming an existing unmanaged row transfers
            // ownership. is_system is NOT in the update payload — never downgrade a system row.
            $data = [
                'name' => $perm['name'] ?? $slug,
                'slug' => $slug,
                'description' => $perm['description'] ?? null,
                'category' => $perm['category'] ?? null,
                'resource_type' => $perm['resource_type'] ?? null,
                'managed_by' => $perm['managed_by'] ?? null,
            ];

            if ($existing === null) {
                $createdModel = $repo->createPermission($data + ['is_system' => false]);
                if ($createdModel !== null) {
                    $slugToUuid[$slug] = $createdModel->getUuid();
                }
                $created++;
                continue;
            }

            $slugToUuid[$slug] = $existing->getUuid();
            if ($this->permissionDiffers($existing, $data)) {
                $repo->update($existing->getUuid(), $data);
                $updated++;
            } else {
                $unchanged++;
            }
        }

        $this->syncRoles($roles, $slugToUuid);

        // Stale = managed rows (managed_by IS NOT NULL) no longer declared.
        $stale = [];
        foreach (array_keys($this->getManagedCatalog()) as $slug) {
            if (!isset($declaredSlugs[$slug])) {
                $stale[] = $slug;
            }
        }

        // Catalog sync rewrites permissions and role grants — cached decisions,
        // user permission sets, and role_permission:* check results are all
        // potentially stale now.
        if ($created > 0 || $updated > 0 || $roles !== []) {
            $this->invalidateAllCache();
        }

        return new SyncResult($created, $updated, $unchanged, $stale);
    }

    /** @param array<string,mixed> $data */
    private function permissionDiffers(\Glueful\Extensions\Aegis\Models\Permission $existing, array $data): bool
    {
        return $existing->getName() !== $data['name']
            || $existing->getDescription() !== $data['description']
            || $existing->getCategory() !== $data['category']
            || $existing->getResourceType() !== $data['resource_type']
            || $existing->getManagedBy() !== $data['managed_by']; // claim/transfer ownership
    }

    /**
     * @param array<int, array<string,mixed>> $roles
     * @param array<string, string> $slugToUuid permission slug => uuid captured during this sync
     */
    private function syncRoles(array $roles, array $slugToUuid): void
    {
        if (count($roles) === 0) {
            return;
        }
        $roleRepo = $this->getRoleRepository();
        $permRepo = $this->getPermissionRepository();
        $rolePermRepo = $this->getRolePermissionRepository();

        foreach ($roles as $role) {
            $slug = (string) $role['slug'];
            $existing = $roleRepo->findRoleBySlug($slug);
            $data = [
                'name' => $role['name'] ?? $slug,
                'slug' => $slug,
                'description' => $role['description'] ?? null,
                'level' => $role['level'] ?? 0,
                'managed_by' => $role['managed_by'] ?? null,
            ];

            if ($existing === null) {
                $createdRole = $roleRepo->createRole($data + ['is_system' => false]);
                if ($createdRole === null) {
                    continue;
                }
                $roleUuid = $createdRole->getUuid();
            } else {
                $roleUuid = $existing->getUuid();
                $roleRepo->update($roleUuid, $data);
            }

            // Resolve grant slugs to permission UUIDs. Grants are guaranteed non-dangling
            // (framework catalog validate() ran before sync), so every slug resolves; prefer
            // the map captured during this sync over a cache-prone re-lookup.
            $permissionUuids = [];
            foreach (($role['grants'] ?? []) as $grantSlug) {
                if ($grantSlug === '*') {
                    continue; // wildcard grants are not materialized as explicit rows
                }
                $uuid = $slugToUuid[$grantSlug] ?? $permRepo->findPermissionBySlug($grantSlug)?->getUuid();
                if ($uuid !== null) {
                    $permissionUuids[] = $uuid;
                }
            }

            $rolePermRepo->replaceRolePermissions($roleUuid, $permissionUuids);
        }
    }

    public function getAvailableResources(): array
    {
        // Get unique resource types from permissions
        $resourceTypes = $this->getPermissionRepository()->getResourceTypes();
        $result = [];

        foreach ($resourceTypes as $type) {
            $result[$type] = ucfirst(str_replace('_', ' ', $type));
        }

        // Add some common resources
        $commonResources = [
            'users' => 'User Management',
            'roles' => 'Role Management',
            'permissions' => 'Permission Management',
            'system' => 'System Administration'
        ];

        return array_merge($commonResources, $result);
    }

    /**
     * @param array<int, array{permission?: string, resource?: string, options?: array<string, mixed>}> $permissions
     * @param array<string, mixed> $options
     */
    public function batchAssignPermissions(string $userUuid, array $permissions, array $options = []): bool
    {
        $success = true;

        foreach ($permissions as $permissionData) {
            $permission = $permissionData['permission'] ?? '';
            $resource = $permissionData['resource'] ?? '*';
            $permissionOptions = array_merge($options, $permissionData['options'] ?? []);

            if (!$this->assignPermission($userUuid, $permission, $resource, $permissionOptions)) {
                $success = false;
            }
        }

        return $success;
    }

    /**
     * @param array<int, array{permission?: string, resource?: string}> $permissions
     */
    public function batchRevokePermissions(string $userUuid, array $permissions): bool
    {
        $success = true;

        foreach ($permissions as $permissionData) {
            $permission = $permissionData['permission'] ?? '';
            $resource = $permissionData['resource'] ?? '*';

            if (!$this->revokePermission($userUuid, $permission, $resource)) {
                $success = false;
            }
        }

        return $success;
    }

    public function invalidateUserCache(string $userUuid): void
    {
        // Clear memory cache
        unset($this->permissionCache[$userUuid]);

        // Clear user roles cache
        $keysToRemove = [];
        foreach (array_keys($this->userRolesCache) as $cacheKey) {
            if (str_starts_with($cacheKey, $userUuid . ':')) {
                $keysToRemove[] = $cacheKey;
            }
        }
        foreach ($keysToRemove as $key) {
            unset($this->userRolesCache[$key]);
        }

        // Clear the repository-level static caches — they are shared across all
        // repository instances, so a stale entry there would survive everything above.
        UserRoleRepository::forgetUserGlobalCache($userUuid);
        UserPermissionRepository::forgetUserGlobalCache($userUuid);

        // Clear distributed cache if enabled
        if ($this->cacheEnabled && $this->cache !== null) {
            try {
                $userPermissionsKey = $this->generateCacheKey('user_permissions', $userUuid);
                $userRolesKey = $this->generateCacheKey('user_roles', $userUuid);

                $this->cache->delete($userPermissionsKey);
                $this->cache->delete($userRolesKey);

                // Also clear any permission check cache for this user
                $this->clearUserPermissionChecks($userUuid);
            } catch (\Exception $e) {
                error_log("Failed to invalidate cache for user {$userUuid}: " . $e->getMessage());
            }
        }
    }

    public function invalidateAllCache(): void
    {
        // Clear memory caches
        $this->permissionCache = [];
        $this->userRolesCache = [];
        UserRoleRepository::flushGlobalCache();
        UserPermissionRepository::flushGlobalCache();

        // Clear distributed cache if enabled
        if ($this->cacheEnabled && $this->cache !== null) {
            try {
                // Clear all RBAC-related cache keys
                $this->cache->deletePattern($this->cachePrefix . '*');
            } catch (\Exception $e) {
                error_log("Failed to invalidate all RBAC cache: " . $e->getMessage());
            }
        }
    }

    public function getProviderInfo(): array
    {
        return [
            'name' => 'RBAC Permission Provider',
            'version' => \Glueful\Extensions\Aegis\Services\AegisServiceProvider::composerVersion(),
            'description' => 'Hierarchical role-based access control with direct user permissions',
            'capabilities' => [
                'hierarchical_roles',
                'direct_permissions',
                'temporal_permissions',
                'resource_filtering',
                'permission_inheritance',
                'scoped_permissions'
            ],
            'author' => 'Glueful Team'
        ];
    }

    /** @return array<string, mixed> */
    public function healthCheck(): array
    {
        $checks = [];

        try {
            // Test role repository
            $roleCount = $this->getRoleRepository()->countRoles();
            $checks['roles'] = [
                'status' => 'healthy',
                'message' => "Found {$roleCount} roles"
            ];
        } catch (\Exception $e) {
            $checks['roles'] = [
                'status' => 'error',
                'message' => 'Role repository error: ' . $e->getMessage()
            ];
        }

        try {
            // Test permission repository
            $permissionCount = $this->getPermissionRepository()->countPermissions();
            $checks['permissions'] = [
                'status' => 'healthy',
                'message' => "Found {$permissionCount} permissions"
            ];
        } catch (\Exception $e) {
            $checks['permissions'] = [
                'status' => 'error',
                'message' => 'Permission repository error: ' . $e->getMessage()
            ];
        }

        $healthy = array_reduce($checks, fn($carry, $check) => $carry && $check['status'] === 'healthy', true);

        return [
            'status' => $healthy ? 'healthy' : 'error',
            'checks' => $checks,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    // RBAC-specific methods

    public function assignRole(string $userUuid, string $roleSlug, array $options = []): bool
    {
        $role = $this->getRoleRepository()->findRoleBySlug($roleSlug);
        if (!$role) {
            return false;
        }

        $result = $this->getUserRoleRepository()->assignRole($userUuid, $role->getUuid(), $options);

        if ($result) {
            $this->invalidateUserCache($userUuid);
            return true;
        }

        return false;
    }

    public function revokeRole(string $userUuid, string $roleSlug): bool
    {
        $role = $this->getRoleRepository()->findRoleBySlug($roleSlug);
        if (!$role) {
            return false;
        }

        $result = $this->getUserRoleRepository()->revokeRole($userUuid, $role->getUuid());

        if ($result) {
            $this->invalidateUserCache($userUuid);
            return true;
        }

        return false;
    }

    /**
     * @param array<string, mixed> $scope
     * @return list<Role>
     */
    public function getUserRoles(string $userUuid, array $scope = []): array
    {
        $userRoles = $this->getUserRoleRepository()->getUserRoles($userUuid, $scope);
        $roles = [];

        // Extract role UUIDs first
        $roleUuids = [];
        foreach ($userRoles as $userRole) {
            $roleUuids[] = $userRole->getRoleUuid();
        }

        // Batch fetch roles to avoid N+1 queries
        if (!empty($roleUuids)) {
            $rolesMap = [];
            $fetchedRoles = $this->getRoleRepository()->findByUuids($roleUuids);
            foreach ($fetchedRoles as $role) {
                $rolesMap[$role->getUuid()] = $role;
            }

            // Build final result in original order
            foreach ($userRoles as $userRole) {
                $roleUuid = $userRole->getRoleUuid();
                if (isset($rolesMap[$roleUuid])) {
                    $roles[] = $rolesMap[$roleUuid];
                }
            }
        }

        return $roles;
    }

    /** @param array<string, mixed> $scope */
    public function hasRole(string $userUuid, string $roleSlug, array $scope = []): bool
    {
        $role = $this->getRoleRepository()->findRoleBySlug($roleSlug);
        if (!$role) {
            return false;
        }

        return $this->getUserRoleRepository()->hasUserRole($userUuid, $role->getUuid(), $scope);
    }

    // Private helper methods

    /** @param array<string, mixed> $context */
    private function hasDirectPermission(string $userUuid, string $permission, string $resource, array $context): bool
    {
        $permissionModel = $this->getPermissionRepository()->findPermissionBySlug($permission);
        if (!$permissionModel) {
            return false;
        }

        $userPermissions = $this->getUserPermissionRepository()->findByUser($userUuid, [
            'permission_uuid' => $permissionModel->getUuid(),
            'active_only' => true
        ]);

        foreach ($userPermissions as $userPermission) {
            $resourceContext = $resource !== '*' ? ['resource' => $resource] : [];

            if (
                $userPermission->matchesResource($resourceContext) &&
                $userPermission->satisfiesConstraints($context)
            ) {
                return true;
            }
        }

        return false;
    }

    /** @param array<string, mixed> $context */
    private function hasRoleBasedPermission(
        string $userUuid,
        string $permission,
        string $resource,
        array $context = []
    ): bool {
        $userRoles = $this->getUserRoles($userUuid, $this->scopeFromContext($context));

        foreach ($userRoles as $role) {
            if ($this->roleHasPermission($role, $permission, $resource)) {
                return true;
            }

            // Check role hierarchy if enabled
            if ($this->config['enable_hierarchy'] && $this->config['enable_inheritance']) {
                $hierarchy = $this->getRoleRepository()->getRoleHierarchy($role->getUuid());
                foreach ($hierarchy as $parentRole) {
                    if ($this->roleHasPermission($parentRole, $permission, $resource)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    private function scopeFromContext(array $context): array
    {
        $scope = $context['scope'] ?? [];

        return is_array($scope) ? $scope : [];
    }

    private function roleHasPermission(Role $role, string $permission, string $resource): bool
    {
        // Check if permission exists
        $permissionModel = $this->getPermissionRepository()->findPermissionBySlug($permission);
        if (!$permissionModel) {
            return false;
        }

        // Check if role has this permission
        $context = $resource !== '*' ? ['resource' => $resource] : [];
        return $this->getRolePermissionRepository()->roleHasPermission(
            $role->getUuid(),
            $permissionModel->getUuid(),
            $context
        );
    }

    /** @return array<string, list<string>> */
    private function getDirectUserPermissions(string $userUuid): array
    {
        $userPermissions = $this->getUserPermissionRepository()->getUserPermissions($userUuid);
        $permissions = [];

        foreach ($userPermissions as $userPermission) {
            $permission = $this->getPermissionRepository()->findPermissionByUuid($userPermission->getPermissionUuid());
            if ($permission) {
                $resourceFilter = $userPermission->getResourceFilter();
                $resource = $resourceFilter['resource'] ?? '*';

                if (!isset($permissions[$resource])) {
                    $permissions[$resource] = [];
                }

                $permissions[$resource][] = $permission->getSlug();
            }
        }

        return $permissions;
    }

    /** @return array<string, list<string>> */
    private function getRoleBasedPermissions(string $userUuid): array
    {
        $permissions = [];

        // Get user's roles
        $userRoles = $this->getUserRoles($userUuid);

        foreach ($userRoles as $role) {
            // Get permissions for this role
            $rolePermissions = $this->getRolePermissionRepository()->getRolePermissions(
                $role->getUuid(),
                ['active_only' => true]
            );

            foreach ($rolePermissions as $rolePermission) {
                $permission = $this->getPermissionRepository()
                    ->findPermissionByUuid($rolePermission->getPermissionUuid());
                if (!$permission) {
                    continue;
                }

                // Get resource filter
                $resourceFilter = $rolePermission->getResourceFilter();
                $resource = $resourceFilter['resource'] ?? '*';

                if (!isset($permissions[$resource])) {
                    $permissions[$resource] = [];
                }

                // Add permission if not already present
                if (!in_array($permission->getSlug(), $permissions[$resource])) {
                    $permissions[$resource][] = $permission->getSlug();
                }
            }

            // Include inherited permissions if hierarchy is enabled
            if ($this->config['enable_hierarchy'] && $this->config['enable_inheritance']) {
                $hierarchy = $this->getRoleRepository()->getRoleHierarchy($role->getUuid());

                foreach ($hierarchy as $parentRole) {
                    $parentPermissions = $this->getRolePermissionRepository()->getRolePermissions(
                        $parentRole->getUuid(),
                        ['active_only' => true]
                    );

                    foreach ($parentPermissions as $parentPermission) {
                        $permission = $this->getPermissionRepository()
                            ->findPermissionByUuid($parentPermission->getPermissionUuid());
                        if (!$permission) {
                            continue;
                        }

                        $resourceFilter = $parentPermission->getResourceFilter();
                        $resource = $resourceFilter['resource'] ?? '*';

                        if (!isset($permissions[$resource])) {
                            $permissions[$resource] = [];
                        }

                        if (!in_array($permission->getSlug(), $permissions[$resource])) {
                            $permissions[$resource][] = $permission->getSlug();
                        }
                    }
                }
            }
        }

        return $permissions;
    }

    // Cache helper methods

    /** @param array<string, mixed> $context */
    private function generateCacheKey(string $type, string $identifier, array $context = []): string
    {
        $key = $this->cachePrefix . $type . ':' . $identifier;

        if (!empty($context)) {
            $key .= ':' . md5(serialize($context));
        }

        return $key;
    }

    private function clearUserPermissionChecks(string $userUuid): void
    {
        if (!$this->cacheEnabled || $this->cache === null) {
            return;
        }

        try {
            // Clear all permission check cache keys for this user
            $pattern = $this->cachePrefix . 'check:' . $userUuid . ':*';
            $this->cache->deletePattern($pattern);
        } catch (\Exception $e) {
            error_log("Failed to clear permission checks cache for user {$userUuid}: " . $e->getMessage());
        }
    }

}
