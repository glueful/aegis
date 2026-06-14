<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Controllers;

use Glueful\Http\Response;
use Glueful\Extensions\Aegis\Services\RoleService;
use Glueful\Extensions\Aegis\Services\PermissionAssignmentService;
use Glueful\Extensions\Aegis\Services\AuditService;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;
use Glueful\Extensions\Aegis\Http\Concerns\ResolvesActor;
use Glueful\Routing\Attributes\ApiOperation;
use Glueful\Routing\Attributes\ApiResponse;
use Glueful\Routing\Attributes\QueryParam;
use Symfony\Component\HttpFoundation\Request;

/**
 * User Role Controller
 *
 * Handles user-role relationship operations including:
 * - User role assignments and management
 * - User permission overview
 * - Role-based access control for users
 * - Bulk user-role operations
 */
class UserRoleController
{
    use ResolvesActor;

    private RoleService $roleService;
    private PermissionAssignmentService $permissionService;
    private UserRoleRepository $userRoleRepository;
    private AuditService $audit;

    public function __construct(
        RoleService $roleService,
        PermissionAssignmentService $permissionService,
        UserRoleRepository $userRoleRepository,
        AuditService $audit
    ) {
        $this->roleService = $roleService;
        $this->permissionService = $permissionService;
        $this->userRoleRepository = $userRoleRepository;
        $this->audit = $audit;
    }

    /**
     * Get all roles for a specific user.
     */
    #[ApiOperation(
        summary: 'Get user roles',
        description: 'Retrieves all roles assigned to a specific user. '
            . 'Requires the `users.view` permission.',
        tags: ['RBAC Users'],
    )]
    #[QueryParam('scope', description: 'JSON-encoded scope filter')]
    #[ApiResponse(200, description: 'User roles retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'User not found')]
    public function getUserRoles(Request $request): Response
    {
        try {
            $userUuid = $request->attributes->get('user_uuid', '');
            $scope = $request->query->get('scope', '');
            if (is_string($scope) && !empty($scope)) {
                $scope = json_decode($scope, true) ?? [];
            } else {
                $scope = [];
            }

            $roles = $this->roleService->getUserRoles($userUuid, $scope);

            return Response::success($roles, 'User roles retrieved successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Assign multiple roles to a user.
     */
    #[ApiOperation(
        summary: 'Assign roles to user',
        description: 'Assigns multiple roles to a user. Body: `role_uuids` (required), `scope`, '
            . '`expires_at`, `assigned_by`. Requires the `roles.assign` permission.',
        tags: ['RBAC Users'],
    )]
    #[ApiResponse(200, description: 'Roles assigned successfully')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function assignRoles(Request $request): Response
    {
        try {
            $userUuid = $request->attributes->get('user_uuid', '');
            $data = $request->toArray();

            if (empty($data['role_uuids'])) {
                return Response::validation(
                    ['role_uuids' => ['Role UUIDs array is required']],
                    'Validation failed'
                );
            }

            $results = [
                'success' => 0,
                'failed' => 0,
                'errors' => []
            ];

            $actor = $this->actorUuid($request);
            $options = [
                'scope' => $data['scope'] ?? [],
                'expires_at' => $data['expires_at'] ?? null,
                'assigned_by' => $actor,
            ];

            foreach ($data['role_uuids'] as $roleUuid) {
                try {
                    $assigned = $this->roleService->assignRoleToUser($userUuid, $roleUuid, $options);
                    if ($assigned) {
                        $results['success']++;
                        $this->audit->logRoleAssigned($userUuid, $roleUuid, $options, $actor);
                    } else {
                        $results['failed']++;
                        $results['errors'][] = "Failed to assign role {$roleUuid}";
                    }
                } catch (\Exception $e) {
                    $results['failed']++;
                    $results['errors'][] = "Error assigning role {$roleUuid}: " . $e->getMessage();
                }
            }

            return Response::success(
                $results,
                "Role assignment completed: {$results['success']} succeeded, {$results['failed']} failed"
            );
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Revoke specific role from user.
     */
    #[ApiOperation(
        summary: 'Revoke specific role from user',
        description: 'Revokes a specific role from a user. Requires the `roles.assign` permission.',
        tags: ['RBAC Users'],
    )]
    #[ApiResponse(200, description: 'Role revoked successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'User or role not found')]
    public function revokeRole(Request $request): Response
    {
        try {
            $userUuid = $request->attributes->get('user_uuid', '');
            $roleUuid = $request->attributes->get('role_uuid', '');

            $revoked = $this->roleService->revokeRoleFromUser($userUuid, $roleUuid);
            if (!$revoked) {
                return Response::serverError('Failed to revoke role');
            }

            $this->audit->logRoleRevoked($userUuid, $roleUuid, $this->actorUuid($request));

            return Response::success(null, 'Role revoked successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Replace all user roles.
     */
    #[ApiOperation(
        summary: 'Replace user roles',
        description: 'Replaces all of a user\'s roles with the specified set. Body: `role_uuids` (required), '
            . '`scope`, `expires_at`, `assigned_by`. Requires the `roles.assign` permission.',
        tags: ['RBAC Users'],
    )]
    #[ApiResponse(200, description: 'User roles updated successfully')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function replaceUserRoles(Request $request): Response
    {
        try {
            $userUuid = $request->attributes->get('user_uuid', '');
            $data = $request->toArray();

            if (!isset($data['role_uuids']) || !is_array($data['role_uuids'])) {
                return Response::validation(
                    ['role_uuids' => ['Role UUIDs array is required']],
                    'Validation failed'
                );
            }

            $scope = $data['scope'] ?? [];
            $currentRoles = $this->roleService->getUserRoles($userUuid, $scope);
            $currentRoleUuids = array_column(array_column($currentRoles, 'role'), 'uuid');

            $results = [
                'added' => 0,
                'removed' => 0,
                'errors' => []
            ];

            $actor = $this->actorUuid($request);
            $options = [
                'scope' => $scope,
                'expires_at' => $data['expires_at'] ?? null,
                'assigned_by' => $actor,
            ];

            // Remove roles that are no longer assigned
            foreach ($currentRoleUuids as $currentRoleUuid) {
                if (!in_array($currentRoleUuid, $data['role_uuids'])) {
                    try {
                        $this->roleService->revokeRoleFromUser($userUuid, $currentRoleUuid);
                        $results['removed']++;
                        $this->audit->logRoleRevoked($userUuid, $currentRoleUuid, $actor);
                    } catch (\Exception $e) {
                        $results['errors'][] = "Failed to remove role {$currentRoleUuid}: " . $e->getMessage();
                    }
                }
            }

            // Add new roles
            foreach ($data['role_uuids'] as $roleUuid) {
                if (!in_array($roleUuid, $currentRoleUuids)) {
                    try {
                        $this->roleService->assignRoleToUser($userUuid, $roleUuid, $options);
                        $results['added']++;
                        $this->audit->logRoleAssigned($userUuid, $roleUuid, $options, $actor);
                    } catch (\Exception $e) {
                        $results['errors'][] = "Failed to add role {$roleUuid}: " . $e->getMessage();
                    }
                }
            }

            return Response::success(
                $results,
                "Roles updated: {$results['added']} added, {$results['removed']} removed"
            );
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Check if user has specific role.
     */
    #[ApiOperation(
        summary: 'Check if user has role',
        description: 'Checks whether a user has a specific role. Body: `role_slug` (required), `scope`. '
            . 'Requires the `users.view` permission.',
        tags: ['RBAC Users'],
    )]
    #[ApiResponse(200, description: 'Role check completed')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function checkUserRole(Request $request): Response
    {
        try {
            $userUuid = $request->attributes->get('user_uuid', '');
            $data = $request->toArray();

            if (empty($data['role_slug'])) {
                return Response::validation(
                    ['role_slug' => ['Role slug is required']],
                    'Validation failed'
                );
            }

            $scope = $data['scope'] ?? [];
            $hasRole = $this->roleService->userHasRole($userUuid, $data['role_slug'], $scope);

            return Response::success([
                'has_role' => $hasRole,
                'user_uuid' => $userUuid,
                'role_slug' => $data['role_slug'],
                'scope' => $scope
            ], 'Role check completed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get user's complete access overview (roles + permissions).
     */
    #[ApiOperation(
        summary: 'Get user access overview',
        description: 'Retrieves a complete access overview for a user (roles + direct and effective '
            . 'permissions). Requires the `users.view` permission.',
        tags: ['RBAC Users'],
    )]
    #[QueryParam('scope', description: 'JSON-encoded scope filter')]
    #[ApiResponse(200, description: 'User access overview retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function getUserAccessOverview(Request $request): Response
    {
        try {
            $userUuid = $request->attributes->get('user_uuid', '');
            $scope = $request->query->get('scope', '');
            if (is_string($scope) && !empty($scope)) {
                $scope = json_decode($scope, true) ?? [];
            } else {
                $scope = [];
            }

            $overview = [
                'user_uuid' => $userUuid,
                'roles' => $this->roleService->getUserRoles($userUuid, $scope),
                'direct_permissions' => $this->permissionService->getUserDirectPermissions(
                    $userUuid,
                    ['active_only' => true]
                ),
                'effective_permissions' => $this->permissionService->getUserEffectivePermissions($userUuid, $scope)
            ];

            return Response::success($overview, 'User access overview retrieved successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get role assignment history for user.
     */
    #[ApiOperation(
        summary: 'Get user role history',
        description: 'Retrieves a paginated role-assignment history for a user. '
            . 'Requires the `users.view` permission.',
        tags: ['RBAC Users'],
    )]
    #[QueryParam('page', 'integer', description: 'Page number for pagination (default: 1)')]
    #[QueryParam('per_page', 'integer', description: 'Number of items per page (default: 25)')]
    #[QueryParam('include_deleted', 'boolean', description: 'Include deleted role assignments (default: true)')]
    #[ApiResponse(200, description: 'User role history retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function getUserRoleHistory(Request $request): Response
    {
        try {
            $userUuid = $request->attributes->get('user_uuid', '');
            $page = (int) $request->query->get('page', 1);
            $perPage = (int) $request->query->get('per_page', 25);
            $includeDeleted = filter_var($request->query->get('include_deleted', true), FILTER_VALIDATE_BOOLEAN);

            $filters = ['user_uuid' => $userUuid];
            if (!$includeDeleted) {
                $filters['exclude_deleted'] = true;
            }

            $history = $this->userRoleRepository->getUserRoleHistoryPaginated($userUuid, $filters, $page, $perPage);
            $historyData = $history['data'];
            $meta = $history;
            unset($meta['data']);

            return Response::successWithMeta($historyData, $meta, 'User role history retrieved successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Bulk assign role to multiple users.
     */
    #[ApiOperation(
        summary: 'Bulk assign role to users',
        description: 'Assigns a role to multiple users. Body: `user_uuids` (required), `scope`, '
            . '`expires_at`, `assigned_by`. Requires the `roles.assign` permission.',
        tags: ['RBAC Roles'],
    )]
    #[ApiResponse(200, description: 'Bulk role assignment completed')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'Role not found')]
    public function bulkAssignRoleToUsers(Request $request): Response
    {
        try {
            $roleUuid = $request->attributes->get('role_uuid', '');
            $data = $request->toArray();

            if (empty($data['user_uuids'])) {
                return Response::validation(
                    ['user_uuids' => ['User UUIDs array is required']],
                    'Validation failed'
                );
            }

            $results = [
                'success' => 0,
                'failed' => 0,
                'errors' => []
            ];

            $actor = $this->actorUuid($request);
            $options = [
                'scope' => $data['scope'] ?? [],
                'expires_at' => $data['expires_at'] ?? null,
                'assigned_by' => $actor,
            ];

            foreach ($data['user_uuids'] as $userUuid) {
                try {
                    $assigned = $this->roleService->assignRoleToUser($userUuid, $roleUuid, $options);
                    if ($assigned) {
                        $results['success']++;
                        $this->audit->logRoleAssigned($userUuid, $roleUuid, $options, $actor);
                    } else {
                        $results['failed']++;
                        $results['errors'][] = "Failed to assign role to user {$userUuid}";
                    }
                } catch (\Exception $e) {
                    $results['failed']++;
                    $results['errors'][] = "Error for user {$userUuid}: " . $e->getMessage();
                }
            }

            return Response::success(
                $results,
                "Bulk role assignment completed: {$results['success']} succeeded, {$results['failed']} failed"
            );
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Bulk revoke role from multiple users.
     */
    #[ApiOperation(
        summary: 'Bulk revoke role from users',
        description: 'Revokes a role from multiple users. Body: `user_uuids` (required). '
            . 'Requires the `roles.assign` permission.',
        tags: ['RBAC Roles'],
    )]
    #[ApiResponse(200, description: 'Bulk role revocation completed')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'Role not found')]
    public function bulkRevokeRoleFromUsers(Request $request): Response
    {
        try {
            $roleUuid = $request->attributes->get('role_uuid', '');
            $data = $request->toArray();

            if (empty($data['user_uuids'])) {
                return Response::validation(
                    ['user_uuids' => ['User UUIDs array is required']],
                    'Validation failed'
                );
            }

            $results = [
                'success' => 0,
                'failed' => 0,
                'errors' => []
            ];

            $actor = $this->actorUuid($request);
            foreach ($data['user_uuids'] as $userUuid) {
                try {
                    $revoked = $this->roleService->revokeRoleFromUser($userUuid, $roleUuid);
                    if ($revoked) {
                        $results['success']++;
                        $this->audit->logRoleRevoked($userUuid, $roleUuid, $actor);
                    } else {
                        $results['failed']++;
                        $results['errors'][] = "Failed to revoke role from user {$userUuid}";
                    }
                } catch (\Exception $e) {
                    $results['failed']++;
                    $results['errors'][] = "Error for user {$userUuid}: " . $e->getMessage();
                }
            }

            return Response::success(
                $results,
                "Bulk role revocation completed: {$results['success']} succeeded, {$results['failed']} failed"
            );
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get user role statistics.
     */
    #[ApiOperation(
        summary: 'Get user-role statistics',
        description: 'Retrieves statistics about user-role assignments (totals, active/expired counts, '
            . 'users-with-roles count). Requires the `roles.view` permission.',
        tags: ['RBAC Statistics'],
    )]
    #[ApiResponse(200, description: 'User-role statistics retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function stats(): Response
    {
        try {
            $stats = [];

            // Get all user roles to calculate statistics
            $allUserRoles = $this->userRoleRepository->findRoleAssignments();
            $stats['total_assignments'] = count($allUserRoles);

            // Calculate active and expired assignments
            $activeCount = 0;
            $expiredCount = 0;
            $uniqueUsers = [];

            foreach ($allUserRoles as $userRole) {
                $uniqueUsers[$userRole->getUserUuid()] = true;

                if ($userRole->isExpired()) {
                    $expiredCount++;
                } else {
                    $activeCount++;
                }
            }

            $stats['active_assignments'] = $activeCount;
            $stats['expired_assignments'] = $expiredCount;
            $stats['users_with_roles'] = count($uniqueUsers);

            return Response::success($stats, 'User role statistics retrieved successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Cleanup expired role assignments.
     */
    #[ApiOperation(
        summary: 'Cleanup expired role assignments',
        description: 'Removes all expired role assignments. Requires the `roles.assign` permission.',
        tags: ['RBAC Maintenance'],
    )]
    #[ApiResponse(200, description: 'Expired role assignments cleaned up')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function cleanupExpiredRoles(): Response
    {
        try {
            $expired = $this->userRoleRepository->findExpiredRoles();
            $count = $this->userRoleRepository->cleanupExpiredRoles();

            $results = [
                'cleaned' => $count,
                'expired_roles' => $expired
            ];

            return Response::success($results, "Cleaned up {$count} expired role assignments");
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }
}
