<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Controllers;

use Glueful\Http\Response;
use Glueful\Extensions\Aegis\Services\PermissionAssignmentService;
use Glueful\Extensions\Aegis\Services\AuditService;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\UserPermissionRepository;
use Glueful\Extensions\Aegis\Http\Concerns\ResolvesActor;
use Glueful\Http\Exceptions\Client\NotFoundException;
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
     * Get all permissions
     *
     * @route GET /api/rbac/permissions
     */
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
     * Get a single permission with details
     *
     * @route GET /api/rbac/permissions/{uuid}
     */
    public function show(Request $request): Response
    {
        try {
            $uuid = $request->attributes->get('uuid', '');

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
     * Create a new permission
     *
     * @route POST /api/rbac/permissions
     */
    public function create(Request $request): Response
    {
        try {
            $data = $request->toArray();

            if (empty($data['name']) || empty($data['slug'])) {
                return Response::validation(
                    ['name' => ['Permission name is required'], 'slug' => ['Permission slug is required']],
                    'Validation failed'
                );
            }

            $permission = $this->permissionService->createPermission($data);
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
     * Update an existing permission
     *
     * @route PUT /api/rbac/permissions/{uuid}
     */
    public function update(Request $request): Response
    {
        try {
            $uuid = $request->attributes->get('uuid', '');
            $data = $request->toArray();

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
     * Delete a permission
     *
     * @route DELETE /api/rbac/permissions/{uuid}
     */
    public function delete(Request $request): Response
    {
        try {
            $uuid = $request->attributes->get('uuid', '');
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
     * Assign permission to user
     *
     * @route POST /api/rbac/permissions/{uuid}/assign
     */
    public function assignToUser(Request $request): Response
    {
        try {
            $permissionUuid = $request->attributes->get('uuid', '');
            $data = $request->toArray();

            if (empty($data['user_uuid'])) {
                return Response::validation(
                    ['user_uuid' => ['User UUID is required']],
                    'Validation failed'
                );
            }

            $permission = $this->permissionRepository->findRecordByUuid($permissionUuid);
            if (!$permission) {
                throw new NotFoundException('Permission not found');
            }

            $actor = $this->actorUuid($request);
            $resource = $data['resource'] ?? '*';
            $options = [
                'granted_by' => $actor,
                'expires_at' => $data['expires_at'] ?? null,
                'constraints' => $data['constraints'] ?? null
            ];

            $assigned = $this->permissionService->assignPermissionToUser(
                $data['user_uuid'],
                $permission['slug'],
                $resource,
                $options
            );

            if (!$assigned) {
                return Response::serverError('Failed to assign permission');
            }

            $this->audit->logPermissionAssigned(
                $data['user_uuid'],
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
     * Revoke permission from user
     *
     * @route DELETE /api/rbac/permissions/{uuid}/revoke
     */
    public function revokeFromUser(Request $request): Response
    {
        try {
            $permissionUuid = $request->attributes->get('uuid', '');
            $data = $request->toArray();

            if (empty($data['user_uuid'])) {
                return Response::validation(
                    ['user_uuid' => ['User UUID is required']],
                    'Validation failed'
                );
            }

            $permission = $this->permissionRepository->findRecordByUuid($permissionUuid);
            if (!$permission) {
                throw new NotFoundException('Permission not found');
            }

            $revoked = $this->permissionService->revokePermissionFromUser(
                $data['user_uuid'],
                $permission['slug']
            );

            if ($revoked) {
                $this->audit->logPermissionRevoked($data['user_uuid'], $permissionUuid, $this->actorUuid($request));
            }

            return Response::success(['revoked' => $revoked], 'Permission revocation processed');
        } catch (NotFoundException $e) {
            return Response::notFound($e->getMessage());
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Batch assign permissions to user
     *
     * @route POST /api/rbac/permissions/batch-assign
     */
    public function batchAssign(Request $request): Response
    {
        try {
            $data = $request->toArray();

            if (empty($data['user_uuid']) || empty($data['permissions'])) {
                return Response::validation(
                    ['user_uuid' => ['User UUID is required'], 'permissions' => ['Permissions array is required']],
                    'Validation failed'
                );
            }

            $actor = $this->actorUuid($request);
            $globalOptions = array_merge($data['options'] ?? [], ['granted_by' => $actor]);
            $auditDataBySlug = [];
            foreach ($data['permissions'] as $permissionData) {
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
                $data['user_uuid'],
                $data['permissions'],
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
                    $data['user_uuid'],
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
     * Batch revoke permissions from user
     *
     * @route POST /api/rbac/permissions/batch-revoke
     */
    public function batchRevoke(Request $request): Response
    {
        try {
            $data = $request->toArray();

            if (empty($data['user_uuid']) || empty($data['permission_slugs'])) {
                return Response::validation(
                    [
                        'user_uuid' => ['User UUID is required'],
                        'permission_slugs' => ['Permission slugs array is required']
                    ],
                    'Validation failed'
                );
            }

            $results = $this->permissionService->batchRevokePermissions(
                $data['user_uuid'],
                $data['permission_slugs']
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

                $this->audit->logPermissionRevoked($data['user_uuid'], $permission->getUuid(), $actor);
            }

            return Response::success($results, 'Batch permission revocation completed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get user's direct permissions
     *
     * @route GET /api/rbac/users/{user_uuid}/permissions
     */
    public function getUserDirectPermissions(Request $request): Response
    {
        try {
            $userUuid = $request->attributes->get('user_uuid', '');
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
     * Get user's effective permissions (direct + role-based)
     *
     * @route GET /api/rbac/users/{user_uuid}/effective-permissions
     */
    public function getUserEffectivePermissions(Request $request): Response
    {
        try {
            $userUuid = $request->attributes->get('user_uuid', '');
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
     * Check if user has specific permission
     *
     * @route POST /api/rbac/check-permission
     */
    public function checkPermission(Request $request): Response
    {
        try {
            $data = $request->toArray();

            if (empty($data['user_uuid']) || empty($data['permission'])) {
                return Response::validation(
                    ['user_uuid' => ['User UUID is required'], 'permission' => ['Permission is required']],
                    'Validation failed'
                );
            }

            $hasPermission = $this->permissionService->userHasPermission(
                $data['user_uuid'],
                $data['permission'],
                $data['resource'] ?? '*',
                $data['context'] ?? []
            );

            return Response::success([
                'has_permission' => $hasPermission,
                'user_uuid' => $data['user_uuid'],
                'permission' => $data['permission'],
                'resource' => $data['resource'] ?? '*'
            ], 'Permission check completed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get permission statistics
     *
     * @route GET /api/rbac/permissions/stats
     */
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
     * Cleanup expired permissions
     *
     * @route POST /api/rbac/permissions/cleanup-expired
     */
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
     * Get permission categories
     *
     * @route GET /api/rbac/permissions/categories
     */
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
     * Get resource types
     *
     * @route GET /api/rbac/permissions/resource-types
     */
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
