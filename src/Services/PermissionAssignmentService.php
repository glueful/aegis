<?php

namespace Glueful\Extensions\Aegis\Services;

use Glueful\Extensions\Aegis\AegisPermissionProvider;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\UserPermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;
use Glueful\Extensions\Aegis\Repositories\RolePermissionRepository;
use Glueful\Extensions\Aegis\Models\Permission;
use Glueful\Helpers\Utils;

/**
 * Permission Assignment Service
 *
 * Business logic for permission assignment operations
 *
 * Features:
 * - Direct user permission assignments
 * - Role-based permission management
 * - Batch permission operations
 * - Permission validation and conflicts
 * - Temporal permission handling
 * - Resource-level permissions
 */
class PermissionAssignmentService
{
    private PermissionRepository $permissionRepository;
    private UserPermissionRepository $userPermissionRepository;
    private RoleRepository $roleRepository;
    private UserRoleRepository $userRoleRepository;
    private RolePermissionRepository $rolePermissionRepository;

    // Cache to prevent duplicate queries within a single request
    /** @var array<string, array<string, mixed>> */
    private array $cache = [
        'user_roles' => [],
        'user_permissions' => [],
        'role_permissions' => []
    ];

    public function __construct(
        PermissionRepository $permissionRepository,
        UserPermissionRepository $userPermissionRepository,
        RoleRepository $roleRepository,
        UserRoleRepository $userRoleRepository,
        RolePermissionRepository $rolePermissionRepository,
        private readonly ?AegisPermissionProvider $permissionProvider = null
    ) {
        $this->permissionRepository = $permissionRepository;
        $this->userPermissionRepository = $userPermissionRepository;
        $this->roleRepository = $roleRepository;
        $this->userRoleRepository = $userRoleRepository;
        $this->rolePermissionRepository = $rolePermissionRepository;
    }

    /**
     * Drop cached state for one user after a privilege mutation — both this
     * service's request-local cache and the provider's distributed decision
     * caches. Without the provider call, a revoked permission stays effective
     * (and a fresh grant stays masked by a cached negative) until the TTL.
     */
    private function invalidateUserPermissionState(string $userUuid): void
    {
        foreach (array_keys($this->cache['user_permissions']) as $key) {
            if (str_starts_with((string) $key, $userUuid . '_')) {
                unset($this->cache['user_permissions'][$key]);
            }
        }
        foreach (array_keys($this->cache['user_roles']) as $key) {
            if (str_starts_with((string) $key, $userUuid . '_')) {
                unset($this->cache['user_roles'][$key]);
            }
        }

        $this->permissionProvider?->invalidateUserCache($userUuid);
    }

    /**
     * Assign permission directly to user
     *
     * @param array<string, mixed> $options
     */
    public function assignPermissionToUser(
        string $userUuid,
        string $permissionSlug,
        string $resource = '*',
        array $options = []
    ): bool {
        $permission = $this->permissionRepository->findPermissionBySlug($permissionSlug);
        if (!$permission) {
            throw new \InvalidArgumentException('Permission not found: ' . $permissionSlug);
        }

        // Check if permission already exists
        $existing = $this->userPermissionRepository->findUserPermission($userUuid, $permission->getUuid());
        if ($existing) {
            return true; // Already assigned
        }

        $data = [
            'user_uuid' => $userUuid,
            'permission_uuid' => $permission->getUuid(),
            'granted_by' => $options['granted_by'] ?? null,
            'expires_at' => $options['expires_at'] ?? null
        ];

        // Set resource filter if not global
        if ($resource !== '*') {
            $data['resource_filter'] = json_encode(['resource' => $resource]);
        }

        // Set constraints if provided
        if (isset($options['constraints'])) {
            $data['constraints'] = json_encode($options['constraints']);
        }

        try {
            $result = $this->userPermissionRepository->create($data);
            if (!empty($result)) {
                $this->invalidateUserPermissionState($userUuid);
                return true;
            }
            return false;
        } catch (\Exception) {
            return false;
        }
    }

    /**
     * Revoke permission from user
     */
    public function revokePermissionFromUser(string $userUuid, string $permissionSlug): bool
    {
        $permission = $this->permissionRepository->findPermissionBySlug($permissionSlug);
        if (!$permission) {
            return false; // Permission doesn't exist, consider it revoked
        }

        $revoked = $this->userPermissionRepository->revokeUserPermission($userUuid, $permission->getUuid());

        if ($revoked) {
            $this->invalidateUserPermissionState($userUuid);
        }

        return $revoked;
    }

    /**
     * Batch assign permissions to user
     *
     * @param list<array<string, mixed>> $permissions
     * @param array<string, mixed> $globalOptions
     * @return array<string, mixed>
     */
    public function batchAssignPermissions(string $userUuid, array $permissions, array $globalOptions = []): array
    {
        $results = [];
        $successful = 0;
        $failed = 0;

        foreach ($permissions as $permissionData) {
            $slug = $permissionData['permission'] ?? '';
            $resource = $permissionData['resource'] ?? '*';
            $options = array_merge($globalOptions, $permissionData['options'] ?? []);

            try {
                $success = $this->assignPermissionToUser($userUuid, $slug, $resource, $options);
                $results[] = [
                    'permission' => $slug,
                    'resource' => $resource,
                    'success' => $success,
                    'error' => null
                ];

                if ($success) {
                    $successful++;
                } else {
                    $failed++;
                }
            } catch (\Exception $e) {
                $results[] = [
                    'permission' => $slug,
                    'resource' => $resource,
                    'success' => false,
                    'error' => $e->getMessage()
                ];
                $failed++;
            }
        }

        return [
            'total' => count($permissions),
            'successful' => $successful,
            'failed' => $failed,
            'results' => $results
        ];
    }

    /**
     * Batch revoke permissions from user
     *
     * @param list<string> $permissionSlugs
     * @return array<string, mixed>
     */
    public function batchRevokePermissions(string $userUuid, array $permissionSlugs): array
    {
        $results = [];
        $successful = 0;
        $failed = 0;

        foreach ($permissionSlugs as $slug) {
            try {
                $success = $this->revokePermissionFromUser($userUuid, $slug);
                $results[] = [
                    'permission' => $slug,
                    'success' => $success,
                    'error' => null
                ];

                if ($success) {
                    $successful++;
                } else {
                    $failed++;
                }
            } catch (\Exception $e) {
                $results[] = [
                    'permission' => $slug,
                    'success' => false,
                    'error' => $e->getMessage()
                ];
                $failed++;
            }
        }

        return [
            'total' => count($permissionSlugs),
            'successful' => $successful,
            'failed' => $failed,
            'results' => $results
        ];
    }

    /**
     * Get user's direct permissions
     *
     * @param array<string, mixed> $filters
     * @return list<array<string, mixed>>
     */
    public function getUserDirectPermissions(string $userUuid, array $filters = []): array
    {
        // Create cache key based on user UUID and filters
        $cacheKey = $userUuid . '_' . md5(serialize($filters));

        if (isset($this->cache['user_permissions'][$cacheKey])) {
            return $this->cache['user_permissions'][$cacheKey];
        }
        $userPermissions = $this->userPermissionRepository->findByUser($userUuid, $filters);

        if (empty($userPermissions)) {
            return [];
        }

        // Extract permission UUIDs for bulk fetching to avoid N+1 queries
        $permissionUuids = array_map(function ($userPermission) {
            return $userPermission->getPermissionUuid();
        }, $userPermissions);

        // Fetch all permissions in a single query
        $permissionsMap = [];
        $permissionUuids = array_unique($permissionUuids); // Remove duplicates
        $permissions = $this->permissionRepository->findByUuids($permissionUuids);

        // Create a map for quick lookup
        foreach ($permissions as $permission) {
            $permissionsMap[$permission->getUuid()] = $permission;
        }

        // Build the result array with permission data
        $permissions = [];
        foreach ($userPermissions as $userPermission) {
            $permission = $permissionsMap[$userPermission->getPermissionUuid()] ?? null;
            if ($permission) {
                $permissions[] = [
                    'permission' => $permission,
                    'assignment' => $userPermission,
                    'resource_filter' => $userPermission->getResourceFilter(),
                    'constraints' => $userPermission->getConstraints(),
                    'expires_at' => $userPermission->getExpiresAt(),
                    'granted_by' => $userPermission->getGrantedBy()
                ];
            }
        }

        // Cache the result
        $this->cache['user_permissions'][$cacheKey] = $permissions;

        return $permissions;
    }

    /**
     * Get user's effective permissions (direct + role-based)
     *
     * @param array<string, mixed> $scope
     * @return array<string, list<array<string, mixed>>>
     */
    public function getUserEffectivePermissions(string $userUuid, array $scope = []): array
    {
        $effectivePermissions = [];

        // Get direct permissions
        $directPermissions = $this->getUserDirectPermissions($userUuid, ['active_only' => true]);
        foreach ($directPermissions as $permData) {
            $slug = $permData['permission']->getSlug();
            $resourceFilter = $permData['resource_filter'];
            $resource = $resourceFilter['resource'] ?? '*';

            if (!isset($effectivePermissions[$resource])) {
                $effectivePermissions[$resource] = [];
            }

            $effectivePermissions[$resource][] = [
                'permission' => $slug,
                'source' => 'direct',
                'expires_at' => $permData['expires_at'],
                'constraints' => $permData['constraints']
            ];
        }

        // Get role-based permissions
        $rolePermissions = $this->getUserRolePermissions($userUuid, $scope);
        foreach ($rolePermissions as $resource => $permissions) {
            if (!isset($effectivePermissions[$resource])) {
                $effectivePermissions[$resource] = [];
            }

            foreach ($permissions as $permission) {
                $effectivePermissions[$resource][] = [
                    'permission' => $permission['permission'],
                    'source' => 'role',
                    'role' => $permission['role'],
                    'expires_at' => $permission['expires_at']
                ];
            }
        }

        return $effectivePermissions;
    }

    /**
     * Check if user has specific permission
     *
     * @param array<string, mixed> $context
     */
    public function userHasPermission(
        string $userUuid,
        string $permissionSlug,
        string $resource = '*',
        array $context = []
    ): bool {
        $permission = $this->permissionRepository->findPermissionBySlug($permissionSlug);
        if (!$permission) {
            return false;
        }

        // Check direct permissions first
        if ($this->hasDirectPermission($userUuid, $permission->getUuid(), $resource, $context)) {
            return true;
        }

        // Check role-based permissions
        return $this->hasRoleBasedPermission($userUuid, $permission->getUuid(), $resource, $context);
    }

    /**
     * Create a new permission
     *
     * @param array<string, mixed> $data
     */
    public function createPermission(array $data): ?Permission
    {
        // Validate required fields
        if (empty($data['name']) || empty($data['slug'])) {
            throw new \InvalidArgumentException('Permission name and slug are required');
        }

        // Check for duplicates
        if ($this->permissionRepository->permissionExists($data['name'])) {
            throw new \InvalidArgumentException('Permission name already exists');
        }

        if ($this->permissionRepository->slugExists($data['slug'])) {
            throw new \InvalidArgumentException('Permission slug already exists');
        }

        // Set defaults
        $data['uuid'] = $data['uuid'] ?? Utils::generateNanoID();
        $data['is_system'] = $data['is_system'] ?? false;
        $data['metadata'] = isset($data['metadata']) ? json_encode($data['metadata']) : null;

        return $this->permissionRepository->createPermission($data);
    }

    /**
     * Update an existing permission
     *
     * @param array<string, mixed> $data
     */
    public function updatePermission(string $uuid, array $data): bool
    {
        $permission = $this->permissionRepository->findPermissionByUuid($uuid);
        if (!$permission) {
            throw new \InvalidArgumentException('Permission not found');
        }

        // Protect system permissions
        if ($permission->isSystem()) {
            $protectedFields = ['is_system', 'slug'];
            foreach ($protectedFields as $field) {
                if (isset($data[$field])) {
                    throw new \InvalidArgumentException("Cannot modify {$field} for system permissions");
                }
            }
        }

        // Validate uniqueness if changed
        if (isset($data['name']) && $data['name'] !== $permission->getName()) {
            if ($this->permissionRepository->permissionExists($data['name'], $uuid)) {
                throw new \InvalidArgumentException('Permission name already exists');
            }
        }

        if (isset($data['slug']) && $data['slug'] !== $permission->getSlug()) {
            if ($this->permissionRepository->slugExists($data['slug'], $uuid)) {
                throw new \InvalidArgumentException('Permission slug already exists');
            }
        }

        // Encode metadata if provided
        if (isset($data['metadata']) && is_array($data['metadata'])) {
            $data['metadata'] = json_encode($data['metadata']);
        }

        $updated = $this->permissionRepository->update($uuid, $data);

        // Slug/metadata changes affect every cached decision that named this
        // permission — there is no per-permission cache index, so clear broadly.
        if ($updated) {
            $this->cache = ['user_roles' => [], 'user_permissions' => [], 'role_permissions' => []];
            $this->permissionProvider?->invalidateAllCache();
        }

        return $updated;
    }

    /**
     * Delete a permission
     */
    public function deletePermission(string $uuid, bool $force = false): bool
    {
        $permission = $this->permissionRepository->findPermissionByUuid($uuid);
        if (!$permission) {
            throw new \InvalidArgumentException('Permission not found');
        }

        // Protect system permissions
        if ($permission->isSystem() && !$force) {
            throw new \InvalidArgumentException('Cannot delete system permissions');
        }

        // Check for assignments
        $assignments = $this->userPermissionRepository->findByPermission($uuid);
        if (!empty($assignments) && !$force) {
            throw new \InvalidArgumentException('Cannot delete permission: still assigned to users');
        }

        // If force delete, remove all assignments
        if ($force) {
            foreach ($assignments as $assignment) {
                $this->userPermissionRepository->delete($assignment->getUuid());
            }
        }

        $deleted = $this->permissionRepository->delete($uuid);

        if ($deleted) {
            $this->cache = ['user_roles' => [], 'user_permissions' => [], 'role_permissions' => []];
            $this->permissionProvider?->invalidateAllCache();
        }

        return $deleted;
    }

    /**
     * Cleanup expired permissions
     *
     * @return array<string, mixed>
     */
    public function cleanupExpiredPermissions(): array
    {
        $expired = $this->userPermissionRepository->findExpiredPermissions();
        $count = $this->userPermissionRepository->cleanupExpiredPermissions();

        return [
            'cleaned' => $count,
            'expired_permissions' => $expired
        ];
    }

    // Private helper methods

    /**
     * @param array<string, mixed> $context
     */
    private function hasDirectPermission(
        string $userUuid,
        string $permissionUuid,
        string $resource,
        array $context
    ): bool {
        $userPermissions = $this->userPermissionRepository->findByUser($userUuid, [
            'permission_uuid' => $permissionUuid,
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

    /**
     * @param array<string, mixed> $context
     */
    private function hasRoleBasedPermission(
        string $userUuid,
        string $permissionUuid,
        string $resource,
        array $context
    ): bool {
        // Get user's active roles
        $userRoles = $this->userRoleRepository->getUserRoles($userUuid, $context['scope'] ?? []);

        if (empty($userRoles)) {
            return false;
        }

        // Check each role for the permission
        foreach ($userRoles as $userRole) {
            $role = $this->roleRepository->findRoleByUuid($userRole->getRoleUuid());
            if (!$role) {
                continue;
            }

            // Check if this role has the permission
            if ($this->roleHasPermission($role->getUuid(), $permissionUuid, $resource)) {
                return true;
            }

            // Check role hierarchy (parent roles) if inheritance is enabled
            $parentRoles = $this->roleRepository->getRoleHierarchy($role->getUuid());
            foreach ($parentRoles as $parentRole) {
                if ($this->roleHasPermission($parentRole->getUuid(), $permissionUuid, $resource)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed> $scope
     * @return array<string, list<array<string, mixed>>>
     */
    private function getUserRolePermissions(string $userUuid, array $scope): array
    {
        $rolePermissions = [];

        // Get user's active roles (with caching)
        $cacheKey = $userUuid . '_' . md5(serialize($scope));
        if (isset($this->cache['user_roles'][$cacheKey])) {
            $userRoles = $this->cache['user_roles'][$cacheKey];
        } else {
            $userRoles = $this->userRoleRepository->getUserRoles($userUuid, $scope);
            $this->cache['user_roles'][$cacheKey] = $userRoles;
        }

        foreach ($userRoles as $userRole) {
            $role = $this->roleRepository->findRoleByUuid($userRole->getRoleUuid());
            if (!$role) {
                continue;
            }

            // Get permissions for this role
            $permissions = $this->getRolePermissions($role->getUuid());

            foreach ($permissions as $permission) {
                $resourceFilter = $permission['resource_filter'] ?? ['resource' => '*'];
                $resource = $resourceFilter['resource'] ?? '*';

                if (!isset($rolePermissions[$resource])) {
                    $rolePermissions[$resource] = [];
                }

                $rolePermissions[$resource][] = [
                    'permission' => $permission['permission_slug'],
                    'role' => $role->getName(),
                    'role_uuid' => $role->getUuid(),
                    'expires_at' => $userRole->getExpiresAt()
                ];
            }

            // Include inherited permissions from parent roles
            $parentRoles = $this->roleRepository->getRoleHierarchy($role->getUuid());
            foreach ($parentRoles as $parentRole) {
                $parentPermissions = $this->getRolePermissions($parentRole->getUuid());

                foreach ($parentPermissions as $permission) {
                    $resourceFilter = $permission['resource_filter'] ?? ['resource' => '*'];
                    $resource = $resourceFilter['resource'] ?? '*';

                    if (!isset($rolePermissions[$resource])) {
                        $rolePermissions[$resource] = [];
                    }

                    // Mark as inherited
                    $rolePermissions[$resource][] = [
                        'permission' => $permission['permission_slug'],
                        'role' => $parentRole->getName(),
                        'role_uuid' => $parentRole->getUuid(),
                        'inherited_from' => $role->getName(),
                        'expires_at' => $userRole->getExpiresAt()
                    ];
                }
            }
        }

        return $rolePermissions;
    }

    /**
     * Check if a role has a specific permission
     */
    private function roleHasPermission(string $roleUuid, string $permissionUuid, string $resource): bool
    {
        $context = $resource !== '*' ? ['resource' => $resource] : [];

        return $this->rolePermissionRepository->roleHasPermission(
            $roleUuid,
            $permissionUuid,
            $context
        );
    }

    /**
     * Get all permissions for a role
     *
     * @return list<array<string, mixed>>
     */
    private function getRolePermissions(string $roleUuid): array
    {
        // Check cache first
        if (isset($this->cache['role_permissions'][$roleUuid])) {
            return $this->cache['role_permissions'][$roleUuid];
        }
        $rolePermissions = $this->rolePermissionRepository->getRolePermissions(
            $roleUuid,
            ['active_only' => true]
        );

        if (empty($rolePermissions)) {
            return [];
        }

        // Extract all permission UUIDs and fetch permissions in bulk
        $permissionUuids = array_map(
            fn($rolePermission) => $rolePermission->getPermissionUuid(),
            $rolePermissions
        );

        $bulkPermissions = $this->permissionRepository->findByUuids(array_unique($permissionUuids));
        // Create a map for quick lookup
        $permissionMap = [];
        foreach ($bulkPermissions as $permission) {
            $permissionMap[$permission->getUuid()] = $permission;
        }

        $permissions = [];
        foreach ($rolePermissions as $rolePermission) {
            $permissionUuid = $rolePermission->getPermissionUuid();
            if (isset($permissionMap[$permissionUuid])) {
                $permission = $permissionMap[$permissionUuid];
                $permissions[] = [
                    'permission_slug' => $permission->getSlug(),
                    'permission_name' => $permission->getName(),
                    'resource_filter' => $rolePermission->getResourceFilter()
                ];
            }
        }

        // Cache the result
        $this->cache['role_permissions'][$roleUuid] = $permissions;

        return $permissions;
    }

    /**
     * Get user's effective permissions using pre-fetched data to avoid duplicate queries
     *
     * @param string $userUuid
     * @param list<array<string, mixed>> $directPermissions Already fetched direct permissions
     * @param list<array<string, mixed>> $roles Already fetched user roles
     * @param array<string, mixed> $scope Optional scope filter
     * @return array<string, list<array<string, mixed>>>
     */
    public function getUserEffectivePermissionsOptimized(
        string $userUuid,
        array $directPermissions = [],
        array $roles = [],
        array $scope = []
    ): array {
        $effectivePermissions = [];

        // Process direct permissions
        foreach ($directPermissions as $permData) {
            $slug = $permData['permission']->getSlug();
            $resourceFilter = $permData['resource_filter'];
            $resource = $resourceFilter['resource'] ?? '*';

            if (!isset($effectivePermissions[$resource])) {
                $effectivePermissions[$resource] = [];
            }

            $effectivePermissions[$resource][] = [
                'permission' => $slug,
                'source' => 'direct',
                'expires_at' => $permData['expires_at'],
                'constraints' => $permData['constraints']
            ];
        }

        // Process role-based permissions using pre-fetched roles
        foreach ($roles as $roleData) {
            $role = $roleData['role'] ?? null;
            if (!$role || !isset($role->uuid)) {
                continue;
            }

            $rolePermissions = $this->getRolePermissions($role->uuid);
            foreach ($rolePermissions as $permission) {
                $resource = $permission['resource_filter'] ?? '*';

                if (!isset($effectivePermissions[$resource])) {
                    $effectivePermissions[$resource] = [];
                }

                $effectivePermissions[$resource][] = [
                    'permission' => $permission['permission_slug'],
                    'source' => 'role',
                    'role' => $role->name ?? 'Unknown',
                    'expires_at' => null // Role permissions don't expire individually
                ];
            }
        }

        return $effectivePermissions;
    }
}
