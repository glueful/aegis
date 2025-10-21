# Aegis (RBAC) Extension for Glueful

## Overview

Aegis provides a comprehensive, modern Role-Based Access Control (RBAC) system for your Glueful application. It implements hierarchical roles, direct user permissions, resource-level filters, and optional audit logging.

## Features

- **Hierarchical roles**: Create nested roles with inheritance
- **Direct user permissions**: Per-user grants that override role permissions
- **Resource-level filters**: Limit permissions to specific resources/types
- **Temporal permissions**: Expiry on roles and direct grants
- **Scoped access**: Multi-tenant friendly with scoping
- **Audit service**: Structured audit helpers + optional check logging
- **Multi-layer caching**: In-memory + distributed cache via CacheStore
- **REST API**: Full CRUD + assignment endpoints
- **Flexible config**: Tunable caching, inheritance, and logging

## Installation

### Installation (Recommended)

**Install via Composer**

```bash
composer require glueful/aegis

# Rebuild the extensions cache after adding new packages
php glueful extensions:cache
```

Glueful auto-discovers packages of type `glueful-extension` and boots their service providers.

Enable/disable in development:

```bash
# Enable (adds provider to config/extensions.php)
php glueful extensions:enable Aegis

# Disable in dev
php glueful extensions:disable Aegis
```

Run database migrations (if not auto-run by your workflow):

```bash
php glueful migrate:run
```

### Local Development Installation

If you're working locally (without Composer), place the extension in `extensions/Aegis`, ensure `config/extensions.php` has `local_path` pointing to `extensions` (non‑prod).

Enable the provider for development (choose one):

- CLI (recommended):
  ```bash
  php glueful extensions:enable Aegis
  ```

- Manual `config/extensions.php` edit:
  ```php
  return [
      'enabled' => [
          // ... other providers
          Glueful\\Extensions\\Aegis\\Services\\AegisServiceProvider::class,
      ],
      'dev_only' => [
          // Optionally keep Aegis dev-only
      ],
      'local_path' => env('APP_ENV') === 'production' ? null : 'extensions',
      'scan_composer' => true,
  ];
  ```

Run the migrations to create the necessary database tables:
```bash
php glueful migrate run
```

3. Generate API documentation (optional, if your tooling supports it):
```bash
php glueful generate:json doc
```

4. Restart your web server to apply the changes.

### Verify Installation

Check status and details:

```bash
php glueful extensions:list
php glueful extensions:info Aegis
php glueful extensions:why Glueful\\Extensions\\Aegis\\Services\\AegisServiceProvider
```

Post-install checklist:

- Run migrations (if not auto-run): `php glueful migrate run`
- Hit an endpoint to verify: `GET /rbac/roles`
- Rebuild cache after Composer operations: `php glueful extensions:cache`
- Check logs for initialization messages or errors

### Quick Start

Create a role, assign it to a user, and verify via the API. Replace placeholders before running:

- `API_BASE` with your base URL (e.g., http://localhost:8000)
- `TOKEN` with a valid bearer token
- `USER_UUID` with an existing user's UUID

```bash
API_BASE=http://localhost:8000
TOKEN="<YOUR_BEARER_TOKEN>"
USER_UUID="<AN_EXISTING_USER_UUID>"

# 1) Create a role
create_resp=$(curl -s -X POST "$API_BASE/rbac/roles" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Editor",
    "slug": "editor",
    "description": "Can edit content"
  }')

# Extract role UUID (requires jq). If jq is unavailable, inspect $create_resp
ROLE_UUID=$(printf "%s" "$create_resp" | jq -r '.data.uuid')
echo "Created role UUID: $ROLE_UUID"

# 2) Assign the role to a user
curl -s -X POST "$API_BASE/rbac/roles/$ROLE_UUID/assign" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\n    \"user_uuid\": \"$USER_UUID\",\n    \"scope\": {\"tenant_id\": \"tenant_1\"}\n  }" | jq .

# 3a) Verify: list the user's roles
curl -s "$API_BASE/rbac/users/$USER_UUID/roles" \
  -H "Authorization: Bearer $TOKEN" | jq .

# 3b) Verify: explicit role check by slug
curl -s -X POST "$API_BASE/rbac/users/$USER_UUID/check-role" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role_slug": "editor"
  }' | jq .
```

### Quick Start (PHP)

Programmatic equivalent using the container and services:

```php
<?php
use Glueful\Extensions\Aegis\Services\RoleService;
use Glueful\Extensions\Aegis\AegisPermissionProvider;

// Resolve services from the container
$roleService = container()->get(RoleService::class);
$provider = container()->get(AegisPermissionProvider::class);

$userUuid = '<AN_EXISTING_USER_UUID>';

// 1) Create a role
$role = $roleService->createRole([
    'name' => 'Editor',
    'slug' => 'editor',
    'description' => 'Can edit content',
]);

// 2) Assign the role to the user
$roleService->assignRoleToUser($userUuid, $role->getUuid(), [
    'scope' => ['tenant_id' => 'tenant_1'],
]);

// 3a) Verify via provider
$hasRole = $provider->hasRole($userUuid, 'editor');

// 3b) Or verify via RoleService helper
$hasRole2 = $roleService->userHasRole($userUuid, 'editor');

// Optional: check permissions using the permission manager
$permissionManager = container()->get('permission.manager');
$canEdit = $permissionManager->can($userUuid, 'posts.edit', 'post:123');

var_dump([
    'role_uuid' => $role->getUuid(),
    'has_editor_role' => $hasRole,
    'has_editor_role_via_service' => $hasRole2,
    'can_edit_post' => $canEdit,
]);
```

## Database Schema

Aegis creates the following tables:

- `roles`: Role definitions with hierarchy support
- `permissions`: Permission definitions with categories and resource types
- `role_permissions`: Role-to-permission mappings
- `user_roles`: User role assignments with scope and expiry support
- `user_permissions`: Direct user permission assignments
- `permission_audit`: Audit records for permission/role changes

## Configuration

Configuration is loaded from `Aegis/config/rbac.php` and merged by the service provider. Example:

```php
<?php
return [
    'roles' => [
        // Inherit permissions up the role hierarchy
        'inherit_permissions' => true,
        // Maximum depth for hierarchy resolution
        'max_hierarchy_depth' => 10,
    ],
    'permissions' => [
        // Distributed caching for user permissions
        'cache_enabled' => true,
        // TTL for user permissions (seconds)
        'cache_ttl' => 3600,
        'cache_prefix' => 'rbac:',
        // Enable role-permission inheritance
        'inheritance_enabled' => true,
    ],
    'logging' => [
        // When true, logs each permission check (verbose)
        'log_check_operations' => false,
    ],
];
```

## Usage

### Basic Permission Checking

```php
use Glueful\Permissions\PermissionManager;

$permissionManager = container()->get('permission.manager');

// Check if user has permission
$canEdit = $permissionManager->can($userUuid, 'posts.edit', 'post:123');

// Check with additional context (e.g., tenant scope)
$canDelete = $permissionManager->can($userUuid, 'posts.delete', 'post:123', [
    'scope' => ['tenant_id' => 'tenant_1'],
]);
```

### Role Management

```php
use Glueful\Extensions\Aegis\Services\RoleService;

$roleService = container()->get(RoleService::class);

// Create a new role
$adminRole = $roleService->createRole([
    'name' => 'Administrator',
    'slug' => 'admin',
    'description' => 'System administrator with full access',
]);

// Create a child role
$moderatorRole = $roleService->createRole([
    'name' => 'Moderator',
    'slug' => 'moderator',
    'parent_uuid' => $adminRole->getUuid(),
    'description' => 'Content moderator',
]);

// Assign role to user
$roleService->assignRoleToUser($userUuid, $adminRole->getUuid(), [
    'expires_at' => '2024-12-31 23:59:59',
    'scope' => ['tenant_id' => 'tenant_1'],
]);
```

### Permission Management

```php
use Glueful\Extensions\Aegis\Services\PermissionAssignmentService;

$permissionService = container()->get(PermissionAssignmentService::class);

// Create a new permission
$permission = $permissionService->createPermission([
    'name' => 'Edit Posts',
    'slug' => 'posts.edit',
    'description' => 'Ability to edit blog posts',
    'category' => 'content',
    'resource_type' => 'posts',
]);

// Assign permission directly to user (overrides role permissions)
$permissionService->assignPermissionToUser(
    $userUuid,
    'posts.edit',
    'post:123', // Specific resource
    [
        'expires_at' => '2024-06-30 23:59:59',
        'constraints' => ['ip_range' => '192.168.1.0/24'],
    ]
);

// Batch assign permissions
$permissionService->batchAssignPermissions($userUuid, [
    ['permission' => 'posts.read', 'resource' => '*'],
    ['permission' => 'posts.edit', 'resource' => 'post:*'],
    ['permission' => 'comments.moderate', 'resource' => '*'],
]);
```

### Using the RBAC Permission Provider

The Aegis provider is auto-registered with the framework’s permission manager. You can either use the manager (recommended) or get the provider directly:

```php
use Glueful\Extensions\Aegis\AegisPermissionProvider;

// Recommended: use the permission manager for checks
$permissionManager = container()->get('permission.manager');
$can = $permissionManager->can($userUuid, 'posts.edit', 'post:123');

// Direct access to provider when needed
$rbacProvider = container()->get(AegisPermissionProvider::class);

// Assign a role
$rbacProvider->assignRole($userUuid, 'editor', [
    'scope' => ['tenant_id' => 'tenant_1'],
    'expires_at' => '2024-12-31 23:59:59',
]);

// Check if user has role
$hasRole = $rbacProvider->hasRole($userUuid, 'admin');

// Get user's effective permissions
$permissions = $rbacProvider->getUserPermissions($userUuid);
```

## API Endpoints

All endpoints are prefixed with `/rbac` and require authentication. Highlights include:

### Roles
- `GET /rbac/roles` – List roles (with filters/pagination)
- `POST /rbac/roles` – Create a role
- `GET /rbac/roles/{uuid}` – Get role details
- `PUT /rbac/roles/{uuid}` – Update a role
- `DELETE /rbac/roles/{uuid}` – Delete a role
- Extra: `GET /rbac/roles/stats`, bulk operations, assign/revoke users

### Permissions
- `GET /rbac/permissions` – List permissions (with filters/pagination)
- `POST /rbac/permissions` – Create a permission
- `GET /rbac/permissions/{uuid}` – Get permission details
- `PUT /rbac/permissions/{uuid}` – Update a permission
- `DELETE /rbac/permissions/{uuid}` – Delete a permission
- Extra: `GET /rbac/permissions/stats`, `POST /rbac/permissions/cleanup-expired`, categories, resource-types

### Users
- `GET /rbac/users/{user_uuid}/roles` – List a user’s roles
- `POST /rbac/users/{user_uuid}/roles` – Assign roles to a user
- `DELETE /rbac/users/{user_uuid}/roles/{role_uuid}` – Revoke a user’s role
- `GET /rbac/users/{user_uuid}/permissions` – List direct permissions
- `POST /rbac/users/{user_uuid}/permissions` – Grant direct permissions
- `DELETE /rbac/users/{user_uuid}/permissions/{permission_uuid}` – Revoke direct permission

## Hierarchical Roles

The RBAC system supports role hierarchy:

```php
// Create role hierarchy: Admin -> Manager -> Employee
$adminRole = $roleService->createRole([
    'name' => 'Administrator',
    'slug' => 'admin',
    'level' => 0
]);

$managerRole = $roleService->createRole([
    'name' => 'Manager',
    'slug' => 'manager',
    'parent_uuid' => $adminRole->getUuid(),
    'level' => 1
]);

$employeeRole = $roleService->createRole([
    'name' => 'Employee',
    'slug' => 'employee',
    'parent_uuid' => $managerRole->getUuid(),
    'level' => 2
]);

// Users with admin role automatically inherit manager and employee permissions
```

## Scoped Permissions

Support multi-tenant environments with scoped permissions:

```php
// Assign role with scope
$roleService->assignRoleToUser($userUuid, $managerRole->getUuid(), [
    'scope' => [
        'tenant_id' => 'tenant_1',
        'department' => 'marketing'
    ]
]);

// Check permission with scope context
$canAccess = $permissionManager->can($userUuid, 'reports.view', '*', [
    'scope' => ['tenant_id' => 'tenant_1']
]);
```

## Audit Logging

An audit service is provided for RBAC-related events, and permission-check logging can be enabled via config:

```php
use Glueful\Extensions\Aegis\Services\AuditService;

$audit = container()->get(AuditService::class);
$audit->logSecurityEvent('unauthorized_access', ['path' => '/rbac/roles'], $userUuid ?? null);

// In config (Aegis/config/rbac.php):
// 'logging' => ['log_check_operations' => true]
// When enabled, permission checks are logged to the 'rbac_audit' channel.
```

## Caching

- **Memory cache**: In-process caching for the current request
- **Distributed cache**: Backed by `CacheStore` for cross-request caching
- **TTL**: Permission checks cached for 15 minutes; user permissions use `permissions.cache_ttl` (default 3600s)

```php
// Clear a user’s RBAC cache
$rbacProvider->invalidateUserCache($userUuid);

// Clear all RBAC cache entries
$rbacProvider->invalidateAllCache();
```

## Performance Considerations

- Permission checks cached ~15 minutes
- User permissions cached per `permissions.cache_ttl`
- Batched lookups to minimize N+1 queries
- Prefer resource-specific permissions to improve cache effectiveness

## Security Considerations

- System roles/permissions can be protected
- Circular hierarchies are prevented
- All endpoints require authentication and proper permissions
- Optional audit trails improve accountability
- Cache keys include security context

## Migration from Legacy Systems

If migrating from an existing permission system:

1. Export existing roles and permissions
2. Use the batch assignment APIs to recreate the structure
3. Test thoroughly with your existing codebase
4. Update permission checks to use the new RBAC provider

## Troubleshooting

### Common Issues

1. **Permissions not working**: Confirm Aegis is enabled and DB tables exist; use `permission.manager` for checks.
2. **Cache issues**: Clear RBAC cache via `invalidateUserCache()`/`invalidateAllCache()`.
3. **Performance issues**: Enable caching and scope permissions/resources.
4. **Audit logs not appearing**: Enable `logging.log_check_operations` and verify your `rbac_audit` log channel.

### Debugging

Adjust `Aegis/config/rbac.php` to disable caches or enable check logging as needed.

## Requirements

- PHP 8.1 or higher
- Glueful 1.0.0 or higher
- MySQL, PostgreSQL, or SQLite database
- Redis or Memcached (optional, for distributed caching)

## License

This extension is licensed under the same license as the Glueful framework.

## Support

For issues, feature requests, or questions, please create an issue in the repository.
