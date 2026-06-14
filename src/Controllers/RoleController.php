<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Controllers;

use Glueful\Http\Response;
use Glueful\Extensions\Aegis\Services\RoleService;
use Glueful\Extensions\Aegis\Services\AuditService;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Http\Concerns\ResolvesActor;
use Glueful\Http\Exceptions\Client\NotFoundException;
use Glueful\Routing\Attributes\ApiOperation;
use Glueful\Routing\Attributes\ApiResponse;
use Glueful\Routing\Attributes\QueryParam;
use Symfony\Component\HttpFoundation\Request;

/**
 * Role Controller
 *
 * Handles all role-related operations including:
 * - Role CRUD operations
 * - Role hierarchy management
 * - User role assignments
 * - Role statistics and analytics
 */
class RoleController
{
    use ResolvesActor;

    private RoleService $roleService;
    private RoleRepository $roleRepository;
    private AuditService $audit;

    public function __construct(
        RoleService $roleService,
        RoleRepository $roleRepository,
        AuditService $audit
    ) {
        $this->roleService = $roleService;
        $this->roleRepository = $roleRepository;
        $this->audit = $audit;
    }

    /**
     * Get all roles with their hierarchy.
     */
    #[ApiOperation(
        summary: 'List all roles',
        description: 'Retrieves a paginated list of roles with optional filtering, or a hierarchical '
            . 'tree view when `tree=true`. Requires the `roles.view` permission.',
        tags: ['RBAC Roles'],
    )]
    #[QueryParam('page', 'integer', description: 'Page number for pagination (default: 1)')]
    #[QueryParam('per_page', 'integer', description: 'Number of items per page (default: 25)')]
    #[QueryParam('search', description: 'Search term for role name or slug')]
    #[QueryParam('status', description: 'Filter by role status', enum: ['active', 'inactive'])]
    #[QueryParam('level', 'integer', description: 'Filter by role hierarchy level')]
    #[QueryParam('tree', 'boolean', description: 'Return roles as a hierarchical tree structure')]
    #[QueryParam('include_deleted', 'boolean', description: 'Include soft-deleted roles')]
    #[ApiResponse(200, description: 'Roles retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function index(Request $request): Response
    {
        try {
            $page = (int) $request->query->get('page', 1);
            $perPage = (int) $request->query->get('per_page', 25);
            $search = $request->query->get('search', '');
            $status = $request->query->get('status', '');
            $level = $request->query->get('level', '');
            $showTree = filter_var($request->query->get('tree', false), FILTER_VALIDATE_BOOLEAN);

            $includeDeleted = filter_var($request->query->get('include_deleted', false), FILTER_VALIDATE_BOOLEAN);
            $filters = ['exclude_deleted' => !$includeDeleted];
            if ($search) {
                $filters['search'] = $search;
            }
            if ($status) {
                $filters['status'] = $status;
            }
            if ($level !== '') {
                $filters['level'] = (int) $level;
            }

            if ($showTree) {
                $roleTree = $this->roleService->getRoleTree();
                return Response::success($roleTree, 'Role hierarchy retrieved successfully');
            }

            $roles = $this->roleRepository->findAllPaginated($filters, $page, $perPage);
            $rolesData = $roles['data'];
            $meta = $roles;
            unset($meta['data']);

            return Response::successWithMeta($rolesData, $meta, 'Roles retrieved successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get a single role with details.
     */
    #[ApiOperation(
        summary: 'Get role details',
        description: 'Retrieves a role with its hierarchy chain, child roles and assigned-user count. '
            . 'Requires the `roles.view` permission.',
        tags: ['RBAC Roles'],
    )]
    #[ApiResponse(200, description: 'Role details retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'Role not found')]
    public function show(Request $request): Response
    {
        try {
            $uuid = $request->attributes->get('uuid', '');

            $role = $this->roleRepository->findRecordByUuid($uuid);
            if (!$role) {
                throw new NotFoundException('Role not found');
            }

            $roleData = $role;
            $roleData['hierarchy'] = $this->roleService->getRoleHierarchy($uuid);
            $roleData['children'] = $this->roleRepository->findChildren($uuid);

            $userCount = count($this->roleRepository->getUsersWithRole($uuid));
            $roleData['user_count'] = $userCount;

            return Response::success($roleData, 'Role details retrieved successfully');
        } catch (NotFoundException $e) {
            return Response::notFound($e->getMessage());
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Create a new role.
     */
    #[ApiOperation(
        summary: 'Create new role',
        description: 'Creates a role. Body: `name` (required), `slug` (required), `description`, '
            . '`parent_uuid`, `status`, `metadata`. Requires the `roles.create` permission.',
        tags: ['RBAC Roles'],
    )]
    #[ApiResponse(201, description: 'Role created successfully')]
    #[ApiResponse(400, description: 'Invalid request format or validation errors')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(409, description: 'Role name or slug already exists')]
    public function create(Request $request): Response
    {
        try {
            $data = $request->toArray();

            if (empty($data['name']) || empty($data['slug'])) {
                return Response::validation(
                    ['name' => ['Role name is required'], 'slug' => ['Role slug is required']],
                    'Validation failed'
                );
            }

            $role = $this->roleService->createRole($data);
            if (!$role) {
                return Response::serverError('Failed to create role');
            }

            $this->audit->logRoleCreated($role->toArray(), $this->actorUuid($request));

            return Response::created($role->toArray(), 'Role created successfully');
        } catch (\InvalidArgumentException $e) {
            return Response::validation(['error' => [$e->getMessage()]], 'Validation failed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Update an existing role.
     */
    #[ApiOperation(
        summary: 'Update role',
        description: 'Updates a role. Body: `name`, `description`, `parent_uuid`, `status`, `metadata`. '
            . 'Requires the `roles.edit` permission.',
        tags: ['RBAC Roles'],
    )]
    #[ApiResponse(200, description: 'Role updated successfully')]
    #[ApiResponse(400, description: 'Invalid request format or validation errors')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'Role not found')]
    public function update(Request $request): Response
    {
        try {
            $uuid = $request->attributes->get('uuid', '');
            $data = $request->toArray();

            $oldRole = $this->roleRepository->findRecordByUuid($uuid);

            $actor = $this->actorUuid($request);
            $updated = $this->roleService->updateRole($uuid, $data, $actor);
            if (!$updated) {
                return Response::serverError('Failed to update role');
            }

            $role = $this->roleRepository->findRecordByUuid($uuid);
            $this->audit->logRoleUpdated(
                $uuid,
                is_array($oldRole) ? $oldRole : [],
                is_array($role) ? $role : [],
                $actor
            );
            return Response::success($role, 'Role updated successfully');
        } catch (\InvalidArgumentException $e) {
            return Response::validation(['error' => [$e->getMessage()]], 'Validation failed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Delete a role.
     */
    #[ApiOperation(
        summary: 'Delete role',
        description: 'Deletes a role, optionally forcing deletion when it has dependencies. '
            . 'Requires the `roles.delete` permission.',
        tags: ['RBAC Roles'],
    )]
    #[QueryParam('force', 'boolean', description: 'Force delete even if assigned to users or has children')]
    #[ApiResponse(200, description: 'Role deleted successfully')]
    #[ApiResponse(400, description: 'Cannot delete role (has dependencies)')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'Role not found')]
    public function delete(Request $request): Response
    {
        try {
            $uuid = $request->attributes->get('uuid', '');
            $force = filter_var($request->query->get('force', false), FILTER_VALIDATE_BOOLEAN);

            $role = $this->roleRepository->findRecordByUuid($uuid);

            $deleted = $this->roleService->deleteRole($uuid, $force);
            if (!$deleted) {
                return Response::serverError('Failed to delete role');
            }

            $this->audit->logRoleDeleted($uuid, is_array($role) ? $role : [], $this->actorUuid($request));

            return Response::success(null, 'Role deleted successfully');
        } catch (\InvalidArgumentException $e) {
            return Response::validation(['error' => [$e->getMessage()]], 'Validation failed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Assign role to user.
     */
    #[ApiOperation(
        summary: 'Assign role to user',
        description: 'Assigns the role to a user. Body: `user_uuid` (required), `scope`, `expires_at`, '
            . '`assigned_by`. Requires the `roles.assign` permission.',
        tags: ['RBAC Roles'],
    )]
    #[ApiResponse(200, description: 'Role assigned successfully')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'Role or user not found')]
    public function assignToUser(Request $request): Response
    {
        try {
            $roleUuid = $request->attributes->get('uuid', '');
            $data = $request->toArray();

            if (empty($data['user_uuid'])) {
                return Response::validation(['user_uuid' => ['User UUID is required']], 'Validation failed');
            }

            $actor = $this->actorUuid($request);
            $options = [
                'scope' => $data['scope'] ?? [],
                'expires_at' => $data['expires_at'] ?? null,
                'assigned_by' => $actor,
            ];

            $assigned = $this->roleService->assignRoleToUser($data['user_uuid'], $roleUuid, $options);
            if (!$assigned) {
                return Response::serverError('Failed to assign role');
            }

            $this->audit->logRoleAssigned($data['user_uuid'], $roleUuid, $options, $actor);

            return Response::success(null, 'Role assigned successfully');
        } catch (\InvalidArgumentException $e) {
            return Response::validation(['error' => [$e->getMessage()]], 'Validation failed');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Revoke role from user.
     */
    #[ApiOperation(
        summary: 'Revoke role from user',
        description: 'Revokes the role from a user. Body: `user_uuid` (required). '
            . 'Requires the `roles.assign` permission.',
        tags: ['RBAC Roles'],
    )]
    #[ApiResponse(200, description: 'Role revoked successfully')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'Role or user not found')]
    public function revokeFromUser(Request $request): Response
    {
        try {
            $roleUuid = $request->attributes->get('uuid', '');
            $data = $request->toArray();

            if (empty($data['user_uuid'])) {
                return Response::validation(['user_uuid' => ['User UUID is required']], 'Validation failed');
            }

            $revoked = $this->roleService->revokeRoleFromUser($data['user_uuid'], $roleUuid);
            if (!$revoked) {
                return Response::serverError('Failed to revoke role');
            }

            $this->audit->logRoleRevoked($data['user_uuid'], $roleUuid, $this->actorUuid($request));

            return Response::success(null, 'Role revoked successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get users assigned to a role.
     */
    #[ApiOperation(
        summary: 'Get users with role',
        description: 'Retrieves a paginated list of users assigned to the role. '
            . 'Requires the `roles.view` permission.',
        tags: ['RBAC Roles'],
    )]
    #[QueryParam('page', 'integer', description: 'Page number for pagination (default: 1)')]
    #[QueryParam('per_page', 'integer', description: 'Number of items per page (default: 25)')]
    #[ApiResponse(200, description: 'Role users retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    #[ApiResponse(404, description: 'Role not found')]
    public function getUsers(Request $request): Response
    {
        try {
            $uuid = $request->attributes->get('uuid', '');
            $page = (int) $request->query->get('page', 1);
            $perPage = (int) $request->query->get('per_page', 25);

            $role = $this->roleRepository->findRecordByUuid($uuid);
            if (!$role) {
                throw new NotFoundException('Role not found');
            }

            $users = $this->roleRepository->getUsersWithRolePaginated($uuid, $page, $perPage);
            $usersData = $users['data'];
            $meta = $users;
            unset($meta['data']);

            return Response::successWithMeta($usersData, $meta, 'Role users retrieved successfully');
        } catch (NotFoundException $e) {
            return Response::notFound($e->getMessage());
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Get role statistics.
     */
    #[ApiOperation(
        summary: 'Get role statistics',
        description: 'Retrieves aggregate role statistics (totals, active/system counts, by-level breakdown). '
            . 'Requires the `roles.view` permission.',
        tags: ['RBAC Roles'],
    )]
    #[ApiResponse(200, description: 'Role statistics retrieved successfully')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function stats(): Response
    {
        try {
            $stats = [];

            // Use repository methods for role counts
            $stats['total_roles'] = $this->roleRepository->countRoles(['exclude_deleted' => true]);
            $stats['active_roles'] = $this->roleRepository->countRoles([
                'status' => 'active',
                'exclude_deleted' => true
            ]);
            $stats['system_roles'] = $this->roleRepository->countRoles([
                'is_system' => 1,
                'exclude_deleted' => true
            ]);

            // Get all roles to calculate by_level statistics
            $allRoles = $this->roleRepository->findAllRoles(['exclude_deleted' => true]);
            $stats['by_level'] = [];
            foreach ($allRoles as $role) {
                $level = $role->getLevel();
                if (!isset($stats['by_level'][$level])) {
                    $stats['by_level'][$level] = 0;
                }
                $stats['by_level'][$level]++;
            }

            return Response::success($stats, 'Role statistics retrieved successfully');
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }

    /**
     * Bulk role operations.
     */
    #[ApiOperation(
        summary: 'Bulk role operations',
        description: 'Performs a bulk action across multiple roles. Body: `action` (required; one of '
            . 'delete, activate, deactivate), `role_ids` (required), `force`. '
            . 'Requires the `roles.edit` permission.',
        tags: ['RBAC Roles'],
    )]
    #[ApiResponse(200, description: 'Bulk operation completed')]
    #[ApiResponse(400, description: 'Invalid request format')]
    #[ApiResponse(403, description: 'Permission denied')]
    public function bulk(Request $request): Response
    {
        try {
            $data = $request->toArray();

            if (empty($data['action']) || empty($data['role_ids'])) {
                return Response::validation(
                    ['action' => ['Action is required'], 'role_ids' => ['Role IDs are required']],
                    'Validation failed'
                );
            }

            $results = [
                'success' => 0,
                'failed' => 0,
                'errors' => []
            ];

            $actor = $this->actorUuid($request);
            foreach ($data['role_ids'] as $roleUuid) {
                try {
                    $role = $this->roleRepository->findRecordByUuid($roleUuid);
                    if (!$role) {
                        $results['failed']++;
                        $results['errors'][] = "Role {$roleUuid} not found";
                        continue;
                    }

                    switch ($data['action']) {
                        case 'delete':
                            $force = $data['force'] ?? false;
                            if (!$this->roleService->deleteRole($roleUuid, $force)) {
                                throw new \RuntimeException('Delete failed');
                            }
                            $this->audit->logRoleDeleted($roleUuid, $role, $actor);
                            break;
                        case 'activate':
                            if (!$this->roleService->updateRole($roleUuid, ['status' => 'active'], $actor)) {
                                throw new \RuntimeException('Activate failed');
                            }
                            $this->audit->logRoleUpdated(
                                $roleUuid,
                                $role,
                                $this->roleRepository->findRecordByUuid($roleUuid) ?? [],
                                $actor
                            );
                            break;
                        case 'deactivate':
                            if (!$this->roleService->updateRole($roleUuid, ['status' => 'inactive'], $actor)) {
                                throw new \RuntimeException('Deactivate failed');
                            }
                            $this->audit->logRoleUpdated(
                                $roleUuid,
                                $role,
                                $this->roleRepository->findRecordByUuid($roleUuid) ?? [],
                                $actor
                            );
                            break;
                        default:
                            throw new \InvalidArgumentException('Invalid action');
                    }

                    $results['success']++;
                } catch (\Exception $e) {
                    $results['failed']++;
                    $results['errors'][] = "Failed for role {$roleUuid}: " . $e->getMessage();
                }
            }

            return Response::success(
                $results,
                "Bulk operation completed: {$results['success']} succeeded, {$results['failed']} failed"
            );
        } catch (\Exception $e) {
            return Response::serverError($e->getMessage());
        }
    }
}
