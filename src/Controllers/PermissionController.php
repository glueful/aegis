<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Controllers;

use Glueful\Http\Response;
use Glueful\Extensions\Aegis\Services\PermissionAssignmentService;
use Glueful\Extensions\Aegis\Services\AuditService;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\UserPermissionRepository;
use Glueful\Extensions\Aegis\Http\Concerns\ReadsRouteParams;
use Glueful\Extensions\Aegis\Http\Concerns\ResolvesActor;
use Glueful\Extensions\Aegis\Http\DTOs\AssignPermissionToUserData;
use Glueful\Extensions\Aegis\Http\DTOs\BatchAssignPermissionsData;
use Glueful\Extensions\Aegis\Http\DTOs\BatchRevokePermissionsData;
use Glueful\Extensions\Aegis\Http\DTOs\CheckPermissionData;
use Glueful\Extensions\Aegis\Http\DTOs\CreatePermissionData;
use Glueful\Extensions\Aegis\Http\DTOs\RevokePermissionFromUserData;
use Glueful\Extensions\Aegis\Http\DTOs\UpdatePermissionData;
use Glueful\Http\Exceptions\Client\NotFoundException;
use Glueful\Routing\Attributes\ApiOperation;
use Glueful\Routing\Attributes\ApiResponse;
use Glueful\Routing\Attributes\QueryParam;
use Symfony\Component\HttpFoundation\Request;

/**
 * Permission Controller
 *
 * Handles all permission-related operations including:
 * - Permission CRUD operations
 * - User permission assignments
 * - Permission validation and checking
 * - Batch permission operations
 */
class PermissionController
{
    use ReadsRouteParams;
    use ResolvesActor;

    private PermissionAssignmentService $permissionService;
    private PermissionRepository $permissionRepository;
    private UserPermissionRepository $userPermissionRepository;
    private AuditService $audit;

    public function __construct(
        PermissionAssignmentService $permissionService,
        PermissionRepository $permissionRepository,
        UserPermissionRepository $userPermissionRepository,
        AuditService $audit
    ) {
        $this->permissionService = $permissionService;
        $this->permissionRepository = $permissionRepository;
        $this->userPermissionRepository = $userPermissionRepository;
        $this->audit = $audit;
    }

    /**
     * Get all permissions.
     */
    #[ApiOperation(
        summary: 'List all permissions',
        description: 'Retrieves a paginated list of permissions with optional filtering. '
            . 'Requires the `roles.view` permission.',
        tags: ['RBAC Permissions'],
    )]
    #[QueryParam('page', 'integer', description: 'Page number for pagination (default: 1)')]
    #[QueryParam('per_page', 'integer', description: 'Number of items per page (default: 25)')]
    #[QueryParam('search', description: 'Search term for permission name or slug')]
    #[QueryParam('category', description: 'Filter by permission category')]
    #[QueryParam('resource_type', description: 'Filter by resource type')]
    #[ApiResponse(200, description: 'Permissions retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function index(Request $request): Response
    {
        try {
            $page = (int) $request->query->get('page', 1);
            $perPage = (int) $request->query->get('per_page', 25);
            $search = $request->query->get('search', '');
            $category = $request->query->get('category', '');
            $resourceType = $request->query->get('resource_type', '');

            $filters = ['exclude_deleted' => true];
            if ($search) {
                $filters['search'] = $search;
            }
            if ($category) {
                $filters['category'] = $category;
            }
            if ($resourceType) {
                $filters['resource_type'] = $resourceType;
            }

            $permissions = $this->permissionRepository->findAllPaginated($filters, $page, $perPage);

            $permissionsData = $permissions['data'];
            $meta = $permissions;
            unset($meta['data']);

            return Response::successWithMeta($permissionsData, $meta, 'Permissions retrieved successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get a single permission with details.
     */
    #[ApiOperation(
        summary: 'Get permission details',
        description: 'Retrieves a permission with its assigned-user count. '
            . 'Requires the `roles.view` permission.',
        tags: ['RBAC Permissions'],
    )]
    #[ApiResponse(200, description: 'Permission details retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'Permission not found')]
    public function show(Request $request): Response
    {
        try {
            $uuid = $this->routeParam($request, 'uuid');

            $permission = $this->permissionRepository->findRecordByUuid($uuid);
            if (!$permission) {
                throw new NotFoundException('Permission not found');
            }

            $permissionData = $permission;

            $userCount = count($this->permissionRepository->getUsersWithPermission($uuid));
            $permissionData['user_count'] = $userCount;

            return Response::success($permissionData, 'Permission details retrieved successfully');
        } catch (NotFoundException $e) {
            return Response::notFound($e->getMessage());
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Create a new permission.
     */
    #[ApiOperation(
        summary: 'Create new permission',
        description: 'Creates a permission. Body: `name` (required), `slug` (required), `description`, '
            . '`category`, `resource_type`, `metadata`. Requires the `system.config` permission.',
        tags: ['RBAC Permissions'],
    )]
    #[ApiResponse(201, description: 'Permission created successfully')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(409, description: 'Permission name or slug already exists')]
    public function create(CreatePermissionData $input, Request $request): Response
    {
        try {
            $permission = $this->permissionService->createPermission($input->toArray());
            if (!$permission) {
                return Response::serverError('Failed to create permission');
            }

            $this->audit->logPermissionCreated($permission->toArray(), $this->actorUuid($request));

            return Response::created($permission->toArray(), 'Permission created successfully');
        } catch (\InvalidArgumentException $e) {
            return Response::validation(['error' => [$e->getMessage()]], 'Validation failed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Update an existing permission.
     */
    #[ApiOperation(
        summary: 'Update permission',
        description: 'Updates a permission. Body: `name`, `description`, `category`, `metadata`. '
            . 'Requires the `system.config` permission.',
        tags: ['RBAC Permissions'],
    )]
    #[ApiResponse(200, description: 'Permission updated successfully')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'Permission not found')]
    public function update(UpdatePermissionData $input, Request $request): Response
    {
        try {
            $uuid = $this->routeParam($request, 'uuid');
            $data = $input->toArray();

            $oldPermission = $this->permissionRepository->findRecordByUuid($uuid);

            $updated = $this->permissionService->updatePermission($uuid, $data);
            if (!$updated) {
                return Response::serverError('Failed to update permission');
            }

            $permission = $this->permissionRepository->findRecordByUuid($uuid);
            $this->audit->logPermissionUpdated(
                $uuid,
                is_array($oldPermission) ? $oldPermission : [],
                is_array($permission) ? $permission : [],
                $this->actorUuid($request)
            );
            return Response::success($permission, 'Permission updated successfully');
        } catch (\InvalidArgumentException $e) {
            return Response::validation(['error' => [$e->getMessage()]], 'Validation failed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Delete a permission.
     */
    #[ApiOperation(
        summary: 'Delete permission',
        description: 'Deletes a permission, optionally forcing deletion when still assigned. '
            . 'Requires the `system.config` permission.',
        tags: ['RBAC Permissions'],
    )]
    #[QueryParam('force', 'boolean', description: 'Force delete even if assigned to users')]
    #[ApiResponse(200, description: 'Permission deleted successfully')]
    #[ApiResponse(400, description: 'Cannot delete permission (still assigned)')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'Permission not found')]
    public function delete(Request $request): Response
    {
        try {
            $uuid = $this->routeParam($request, 'uuid');
            $force = filter_var($request->query->get('force', false), FILTER_VALIDATE_BOOLEAN);

            $permission = $this->permissionRepository->findRecordByUuid($uuid);

            $deleted = $this->permissionService->deletePermission($uuid, $force);
            if (!$deleted) {
                return Response::serverError('Failed to delete permission');
            }

            $this->audit->logPermissionDeleted($uuid, is_array($permission) ? $permission : [], $this->actorUuid($request));

            return Response::success(null, 'Permission deleted successfully');
        } catch (\InvalidArgumentException $e) {
            return Response::validation(['error' => [$e->getMessage()]], 'Validation failed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Assign permission to user.
     */
    #[ApiOperation(
        summary: 'Assign permission to user',
        description: 'Assigns the permission directly to a user. Body: `user_uuid` (required), `resource`, '
            . '`expires_at`, `constraints`, `granted_by`. Requires the `system.config` permission.',
        tags: ['RBAC Permissions'],
    )]
    #[ApiResponse(200, description: 'Permission assigned successfully')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'Permission or user not found')]
    public function assignToUser(AssignPermissionToUserData $input, Request $request): Response
    {
        try {
            $permissionUuid = $this->routeParam($request, 'uuid');

            $permission = $this->permissionRepository->findRecordByUuid($permissionUuid);
            if (!$permission) {
                throw new NotFoundException('Permission not found');
            }

            $actor = $this->actorUuid($request);
            $resource = $input->resource;
            $options = [
                'granted_by' => $actor,
                'expires_at' => $input->expires_at,
                'constraints' => $input->constraints
            ];

            $assigned = $this->permissionService->assignPermissionToUser(
                $input->user_uuid,
                $permission['slug'],
                $resource,
                $options
            );

            if (!$assigned) {
                return Response::serverError('Failed to assign permission');
            }

            $this->audit->logPermissionAssigned(
                $input->user_uuid,
                $permissionUuid,
                array_merge($options, ['resource' => $resource]),
                $actor
            );

            return Response::success(null, 'Permission assigned successfully');
        } catch (NotFoundException $e) {
            return Response::notFound($e->getMessage());
        } catch (\InvalidArgumentException $e) {
            return Response::validation(['error' => [$e->getMessage()]], 'Validation failed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Revoke permission from user.
     */
    #[ApiOperation(
        summary: 'Revoke permission from user',
        description: 'Revokes the permission from a user. Body: `user_uuid` (required). '
            . 'Requires the `system.config` permission.',
        tags: ['RBAC Permissions'],
    )]
    #[ApiResponse(200, description: 'Permission revoked successfully')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'Permission or user not found')]
    public function revokeFromUser(RevokePermissionFromUserData $input, Request $request): Response
    {
        try {
            $permissionUuid = $this->routeParam($request, 'uuid');

            $permission = $this->permissionRepository->findRecordByUuid($permissionUuid);
            if (!$permission) {
                throw new NotFoundException('Permission not found');
            }

            $revoked = $this->permissionService->revokePermissionFromUser(
                $input->user_uuid,
                $permission['slug']
            );

            if ($revoked) {
                $this->audit->logPermissionRevoked($input->user_uuid, $permissionUuid, $this->actorUuid($request));
            }

            return Response::success(['revoked' => $revoked], 'Permission revocation processed');
        } catch (NotFoundException $e) {
            return Response::notFound($e->getMessage());
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Batch assign permissions to user.
     */
    #[ApiOperation(
        summary: 'Batch assign permissions',
        description: 'Assigns multiple permissions to a user. Body: `user_uuid` (required), '
            . '`permissions` (required; array of {permission, resource, options}), `options`. '
            . 'Requires the `system.config` permission.',
        tags: ['RBAC Permissions'],
    )]
    #[ApiResponse(200, description: 'Batch permission assignment completed')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function batchAssign(BatchAssignPermissionsData $input, Request $request): Response
    {
        try {
            if ($input->permissions === []) {
                return Response::validation(
                    ['permissions' => ['Permissions array is required']],
                    'Validation failed'
                );
            }

            $actor = $this->actorUuid($request);
            $globalOptions = array_merge($input->options, ['granted_by' => $actor]);
            $auditDataBySlug = [];
            foreach ($input->permissions as $permissionData) {
                $slug = $permissionData['permission'] ?? '';
                if ($slug === '') {
                    continue;
                }
                $auditDataBySlug[$slug] = array_merge(
                    $globalOptions,
                    $permissionData['options'] ?? [],
                    ['resource' => $permissionData['resource'] ?? '*']
                );
            }

            $results = $this->permissionService->batchAssignPermissions(
                $input->user_uuid,
                $input->permissions,
                $globalOptions
            );

            foreach ($results['results'] ?? [] as $result) {
                if (($result['success'] ?? false) !== true) {
                    continue;
                }

                $permission = $this->permissionRepository->findPermissionBySlug((string) ($result['permission'] ?? ''));
                if ($permission === null) {
                    continue;
                }

                $this->audit->logPermissionAssigned(
                    $input->user_uuid,
                    $permission->getUuid(),
                    $auditDataBySlug[$result['permission']] ?? ['resource' => $result['resource'] ?? '*'],
                    $actor
                );
            }

            return Response::success($results, 'Batch permission assignment completed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Batch revoke permissions from user.
     */
    #[ApiOperation(
        summary: 'Batch revoke permissions',
        description: 'Revokes multiple permissions from a user. Body: `user_uuid` (required), '
            . '`permission_slugs` (required). Requires the `system.config` permission.',
        tags: ['RBAC Permissions'],
    )]
    #[ApiResponse(200, description: 'Batch permission revocation completed')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function batchRevoke(BatchRevokePermissionsData $input, Request $request): Response
    {
        try {
            if ($input->permission_slugs === []) {
                return Response::validation(
                    ['permission_slugs' => ['Permission slugs array is required']],
                    'Validation failed'
                );
            }

            $results = $this->permissionService->batchRevokePermissions(
                $input->user_uuid,
                $input->permission_slugs
            );

            $actor = $this->actorUuid($request);
            foreach ($results['results'] ?? [] as $result) {
                if (($result['success'] ?? false) !== true) {
                    continue;
                }

                $permission = $this->permissionRepository->findPermissionBySlug((string) ($result['permission'] ?? ''));
                if ($permission === null) {
                    continue;
                }

                $this->audit->logPermissionRevoked($input->user_uuid, $permission->getUuid(), $actor);
            }

            return Response::success($results, 'Batch permission revocation completed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get user's direct permissions.
     */
    #[ApiOperation(
        summary: 'Get user direct permissions',
        description: 'Retrieves all permissions directly assigned to a user (not from roles). '
            . 'Requires the `users.view` permission.',
        tags: ['RBAC Users'],
    )]
    #[QueryParam('active_only', 'boolean', description: 'Return only active permissions (default: true)')]
    #[ApiResponse(200, description: 'User permissions retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function getUserDirectPermissions(Request $request): Response
    {
        try {
            $userUuid = $this->routeParam($request, 'user_uuid');
            $activeOnly = filter_var($request->query->get('active_only', true), FILTER_VALIDATE_BOOLEAN);

            $filters = [];
            if ($activeOnly) {
                $filters['active_only'] = true;
            }

            $permissions = $this->permissionService->getUserDirectPermissions($userUuid, $filters);

            return Response::success($permissions, 'User direct permissions retrieved successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get user's effective permissions (direct + role-based).
     */
    #[ApiOperation(
        summary: 'Get user effective permissions',
        description: 'Retrieves all effective permissions for a user (direct + role-based). '
            . 'Requires the `users.view` permission.',
        tags: ['RBAC Users'],
    )]
    #[QueryParam('scope', description: 'JSON-encoded scope filter')]
    #[ApiResponse(200, description: 'User effective permissions retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function getUserEffectivePermissions(Request $request): Response
    {
        try {
            $userUuid = $this->routeParam($request, 'user_uuid');
            $scope = $request->query->get('scope', '');
            if (is_string($scope) && !empty($scope)) {
                $scope = json_decode($scope, true) ?? [];
            } else {
                $scope = [];
            }

            $permissions = $this->permissionService->getUserEffectivePermissions($userUuid, $scope);

            return Response::success($permissions, 'User effective permissions retrieved successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Check if user has specific permission.
     */
    #[ApiOperation(
        summary: 'Check user permission',
        description: 'Checks whether a user has a specific permission. Body: `user_uuid` (required), '
            . '`permission` (required), `resource`, `context`. Requires the `users.view` permission.',
        tags: ['RBAC Validation'],
    )]
    #[ApiResponse(200, description: 'Permission check completed')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function checkPermission(CheckPermissionData $input, Request $request): Response
    {
        try {
            $hasPermission = $this->permissionService->userHasPermission(
                $input->user_uuid,
                $input->permission,
                $input->resource,
                $input->context
            );

            return Response::success([
                'has_permission' => $hasPermission,
                'user_uuid' => $input->user_uuid,
                'permission' => $input->permission,
                'resource' => $input->resource
            ], 'Permission check completed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get permission statistics.
     */
    #[ApiOperation(
        summary: 'Get permission statistics',
        description: 'Retrieves aggregate permission statistics (totals, system count, by-category and '
            . 'by-resource-type breakdowns, direct assignment count). Requires the `roles.view` permission.',
        tags: ['RBAC Permissions'],
    )]
    #[ApiResponse(200, description: 'Permission statistics retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function stats(): Response
    {
        try {
            $stats = [];

            // Use repository methods for permission counts
            $stats['total_permissions'] = $this->permissionRepository->countPermissions();
            $stats['system_permissions'] = $this->permissionRepository->countPermissions(['is_system' => 1]);

            // Get all permissions to calculate category and resource type statistics
            $allPermissions = $this->permissionRepository->findAllPermissions();

            $stats['by_category'] = [];
            $stats['by_resource_type'] = [];

            foreach ($allPermissions as $permission) {
                $category = $permission->getCategory() ?? 'uncategorized';
                $resourceType = $permission->getResourceType() ?? 'general';

                if (!isset($stats['by_category'][$category])) {
                    $stats['by_category'][$category] = 0;
                }
                $stats['by_category'][$category]++;

                if (!isset($stats['by_resource_type'][$resourceType])) {
                    $stats['by_resource_type'][$resourceType] = 0;
                }
                $stats['by_resource_type'][$resourceType]++;
            }

            // Count direct permission assignments (permissions assigned directly to users, not through roles)
            $stats['direct_assignments'] = $this->userPermissionRepository->countAllUserPermissions();

            return Response::success($stats, 'Permission statistics retrieved successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Cleanup expired permissions.
     */
    #[ApiOperation(
        summary: 'Cleanup expired permissions',
        description: 'Removes all expired permission assignments. Requires the `system.config` permission.',
        tags: ['RBAC Permissions'],
    )]
    #[ApiResponse(200, description: 'Expired permissions cleaned up')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function cleanupExpired(): Response
    {
        try {
            $results = $this->permissionService->cleanupExpiredPermissions();

            return Response::success($results, "Cleaned up {$results['cleaned']} expired permissions");
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get permission categories.
     */
    #[ApiOperation(
        summary: 'Get permission categories',
        description: 'Retrieves all available permission categories. Requires the `roles.view` permission.',
        tags: ['RBAC Permissions'],
    )]
    #[ApiResponse(200, description: 'Permission categories retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function getCategories(): Response
    {
        try {
            $categories = $this->permissionRepository->getCategories();

            return Response::success($categories, 'Permission categories retrieved successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get resource types.
     */
    #[ApiOperation(
        summary: 'Get resource types',
        description: 'Retrieves all available resource types. Requires the `roles.view` permission.',
        tags: ['RBAC Permissions'],
    )]
    #[ApiResponse(200, description: 'Resource types retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function getResourceTypes(): Response
    {
        try {
            $resourceTypes = $this->permissionRepository->getResourceTypes();

            return Response::success($resourceTypes, 'Resource types retrieved successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }
}
