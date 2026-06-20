<?php

/**
 * RBAC Extension Routes
 *
 * This file defines routes for RBAC (Role-Based Access Control) functionality including:
 * - Role management (CRUD operations, hierarchy)
 * - Permission management (CRUD operations, assignments)
 * - User-role relationships
 * - User permission assignments
 * - Permission checking and validation
 * - Statistics and maintenance operations
 *
 * Every route requires authentication (`auth`) AND a specific RBAC permission, enforced by
 * the `aegis_permission:<slug>` middleware (fail-closed). Reads require a view permission
 * (`roles.view`/`users.view`); role mutations require `roles.create|edit|delete|assign`;
 * permission-catalog and direct-permission management require `system.config`.
 *
 * OpenAPI docs for each route live as typed attributes (#[ApiOperation]/#[QueryParam]/#[ApiResponse])
 * on the controller action methods.
 */

use Glueful\Routing\Router;
use Glueful\Extensions\Aegis\Controllers\{
    RoleController,
    PermissionController,
    UserRoleController
};

/** @var Router $router Router instance injected by RouteManifest::load() */

$router->group(['prefix' => '/rbac', 'middleware' => ['auth']], function(Router $router) {

    // Role Management Routes
    $router->group(['prefix' => '/roles', 'middleware' => ['auth']], function(Router $router) {
        $router->get('/', [RoleController::class, 'index'])->middleware('aegis_permission:roles.view');
        $router->get('/stats', [RoleController::class, 'stats'])->middleware('aegis_permission:roles.view');
        $router->post('/bulk', [RoleController::class, 'bulk'])->middleware('aegis_permission:roles.edit');
        $router->get('/{uuid}', [RoleController::class, 'show'])->middleware('aegis_permission:roles.view');
        $router->post('/', [RoleController::class, 'create'])->middleware('aegis_permission:roles.create');
        $router->put('/{uuid}', [RoleController::class, 'update'])->middleware('aegis_permission:roles.edit');
        $router->delete('/{uuid}', [RoleController::class, 'delete'])->middleware('aegis_permission:roles.delete');
        $router->post('/{uuid}/assign', [RoleController::class, 'assignToUser'])->middleware('aegis_permission:roles.assign');
        $router->delete('/{uuid}/revoke', [RoleController::class, 'revokeFromUser'])->middleware('aegis_permission:roles.assign');
        $router->get('/{uuid}/users', [RoleController::class, 'getUsers'])->middleware('aegis_permission:roles.view');
        $router->post('/{role_uuid}/assign-users', [UserRoleController::class, 'bulkAssignRoleToUsers'])->middleware('aegis_permission:roles.assign');
        $router->delete('/{role_uuid}/revoke-users', [UserRoleController::class, 'bulkRevokeRoleFromUsers'])->middleware('aegis_permission:roles.assign');
    });

    // Permission Management Routes
    $router->group(['prefix' => '/permissions', 'middleware' => ['auth']], function (Router $router) {
        $router->get('/', [PermissionController::class, 'index'])->middleware('aegis_permission:roles.view');
        $router->get('/stats', [PermissionController::class, 'stats'])->middleware('aegis_permission:roles.view');
        $router->post('/cleanup-expired', [PermissionController::class, 'cleanupExpired'])->middleware('aegis_permission:system.config');
        $router->get('/categories', [PermissionController::class, 'getCategories'])->middleware('aegis_permission:roles.view');
        $router->get('/resource-types', [PermissionController::class, 'getResourceTypes'])->middleware('aegis_permission:roles.view');
        $router->get('/{uuid}', [PermissionController::class, 'show'])->middleware('aegis_permission:roles.view');
        $router->post('/', [PermissionController::class, 'create'])->middleware('aegis_permission:system.config');
        $router->put('/{uuid}', [PermissionController::class, 'update'])->middleware('aegis_permission:system.config');
        $router->delete('/{uuid}', [PermissionController::class, 'delete'])->middleware('aegis_permission:system.config');
        $router->post('/{uuid}/assign', [PermissionController::class, 'assignToUser'])->middleware('aegis_permission:system.config');
        $router->delete('/{uuid}/revoke', [PermissionController::class, 'revokeFromUser'])->middleware('aegis_permission:system.config');
        $router->post('/batch-assign', [PermissionController::class, 'batchAssign'])->middleware('aegis_permission:system.config');
        $router->post('/batch-revoke', [PermissionController::class, 'batchRevoke'])->middleware('aegis_permission:system.config');
    });

    // User-specific RBAC Routes
    $router->group(['prefix' => '/users', 'middleware' => ['auth']], function (Router $router) {
        $router->get('/{user_uuid}/roles', [UserRoleController::class, 'getUserRoles'])->middleware('aegis_permission:users.view');
        $router->post('/{user_uuid}/roles', [UserRoleController::class, 'assignRoles'])->middleware('aegis_permission:roles.assign');
        $router->put('/{user_uuid}/roles', [UserRoleController::class, 'replaceUserRoles'])->middleware('aegis_permission:roles.assign');
        $router->delete('/{user_uuid}/roles/{role_uuid}', [UserRoleController::class, 'revokeRole'])->middleware('aegis_permission:roles.assign');
        $router->get('/{user_uuid}/permissions', [PermissionController::class, 'getUserDirectPermissions'])->middleware('aegis_permission:users.view');
        $router->get('/{user_uuid}/effective-permissions', [PermissionController::class, 'getUserEffectivePermissions'])->middleware('aegis_permission:users.view');
        $router->get('/{user_uuid}/access-overview', [UserRoleController::class, 'getUserAccessOverview'])->middleware('aegis_permission:users.view');
        $router->get('/{user_uuid}/role-history', [UserRoleController::class, 'getUserRoleHistory'])->middleware('aegis_permission:users.view');
        $router->post('/{user_uuid}/check-role', [UserRoleController::class, 'checkUserRole'])->middleware('aegis_permission:users.view');
    });

    // Permission/Role Checking Routes
    $router->post('/check-permission', [PermissionController::class, 'checkPermission'])->middleware('aegis_permission:users.view');

    // Statistics and Maintenance Routes
    $router->get('/user-roles/stats', [UserRoleController::class, 'stats'])->middleware('aegis_permission:roles.view');
    $router->post('/user-roles/cleanup-expired', [UserRoleController::class, 'cleanupExpiredRoles'])->middleware('aegis_permission:roles.assign');
});
