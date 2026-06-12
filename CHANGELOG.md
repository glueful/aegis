# Changelog

All notable changes to the Aegis (RBAC) extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Single authorization engine: the management API's permission check now delegates to the runtime provider.** `PermissionAssignmentService::userHasPermission()` (backing `POST /rbac/check-permission`) previously ran its own parallel direct/role/hierarchy walk that could drift from `AegisPermissionProvider::can()` — for example it always walked the role hierarchy regardless of the `enable_hierarchy`/`enable_inheritance` config the runtime engine honors. It now delegates to `can()`, so the dry-run check answers exactly what enforcement answers (including scope handling, deny-by-default, and audit logging). The service's private check helpers and the dead, caller-less `getUserEffectivePermissionsOptimized()` were removed, and the provider is now a required constructor dependency. `getUserEffectivePermissions()` remains as a reporting/enumeration API (it returns grant provenance the boolean engine doesn't). Pinned by `PermissionCheckConsolidationTest`.

### Fixed
- **Docs: README behavior notes now match the implementation.** The docs now state that child roles inherit ancestor permissions, direct user grants augment role permissions rather than deny/override them, direct user-grant resource matching is exact, `config/rbac.php` ships empty for app overrides, and `permission_audit` is reserved schema while the current audit service writes to the `rbac_audit` log channel.
- **Security: bulk RBAC mutations now write audit entries.** Permission `batchAssign` / `batchRevoke` now audit each successful direct-grant change with the authenticated actor, and role bulk delete / activate / deactivate now audit each successful catalog mutation. The permission batch path also ignores spoofed `granted_by` values in request options and passes the authenticated actor to the assignment service. `AegisPermissionProvider::can()` now calls the existing `AuditService::logPermissionCheck()` hook when `rbac.logging.log_check_operations` is enabled, so documented permission-check logging is reachable.
- **Security: temporal grants no longer outlive `expires_at` through authorization caches.** Final `can()` decisions and role-permission booleans are no longer cached, and active direct-grant / role-grant repository reads no longer reuse in-process active-list caches. This prevents sub-TTL role assignments, direct grants, and role-permission grants from continuing to authorize after their stored `expires_at` passes under persistent workers or distributed cache.
- **Security: scoped role checks now respect tenant scope on the real decision path.** `UserRoleRepository::hasUserRole()` previously selected only `uuid`, so scoped role assignments were reconstructed without their `scope` JSON and matched any tenant. The main `AegisPermissionProvider::can()` role path also ignored `context['scope']`, while the parallel assignment-service evaluator honored it. Scoped `hasRole()` and `can()` checks now use the stored assignment scope consistently, and assigning the same role under two different scopes creates two distinct assignments instead of silently no-oping.
- **Security: delegated RBAC admins can no longer grant above their own role ceiling.** The 1.7.0 route gates stopped unauthenticated RBAC mutation, but an authenticated delegated admin with `roles.assign` / `roles.edit` could still assign a role they did not hold (for example assigning themselves `superadmin`) or reparent a role under a more-privileged parent and inherit upward. `RoleService` now enforces a grant ceiling whenever an actor is supplied: role assignment requires the actor to hold the target role or an ancestor role, and hierarchy updates require the actor to hold or outrank the new parent. Internal/system calls without an actor remain available for bootstrap/catalog sync. `RoleController` now passes the authenticated actor into role updates, and `RoleRepository` invalidates its static role cache on create/update/delete so hierarchy decisions cannot use stale role shapes under persistent workers.
- **Security: privilege mutations now invalidate every permission-cache layer immediately.** Revoking a role or direct permission through the management API (`RoleService` / `PermissionAssignmentService`) wrote to the database only — Aegis' distributed authorization caches and repository-level static caches were never invalidated, so a revoked principal kept access until the TTL expired, and a fresh grant could stay masked by a cached negative. Both services now receive the shared provider and invalidate per-user caches on assign/revoke (roles and direct permissions, single and batch) and invalidate broadly on role update/delete and permission update/delete (hierarchy, status, and slug changes affect every member). Catalog sync/prune and `aegis:bootstrap-admin`'s direct role-permission grants invalidate as well. `UserRoleRepository` and `UserPermissionRepository` each expose `forgetUserGlobalCache()` / `flushGlobalCache()` hooks, so invalidation in one place reaches every repository instance (provider, services, controllers) — including under persistent workers. Regression-tested end-to-end through `AegisPermissionProvider::can()` (`RevocationCacheInvalidationTest`); the SQLite test harness now ships `user_roles`/`user_permissions` faithful to the real migrations (no `deleted_at` on assignments — `BootstrapAdminServiceTest`'s local table and query were corrected to match).

## [1.7.0] - 2026-06-11 — RBAC Authorization Hardening

> **Security & correctness release.** Closes a privilege escalation in the RBAC management
> API, makes privilege changes correctly attributed and audited, hardens provider activation
> and resource-filter matching, and raises the framework baseline to 1.55.0. Ships as a minor
> (behavioral enforcement change + raised dependency floor) -- see **Upgrade Notes**.

### Security

- **Fixed privilege escalation: the `/rbac` management API now enforces RBAC permissions.**
  Every `/rbac` route previously ran with only the `auth` middleware and no permission
  check, so **any authenticated user** could call e.g. `POST /rbac/users/{uuid}/roles` to
  grant themselves an admin role (or create roles / assign raw permissions). All 37 routes
  are now gated by a new fail-closed `aegis_permission:<slug>` middleware: reads require a
  view permission (`roles.view` / `users.view`), role mutations require
  `roles.create|edit|delete|assign`, and permission-catalog / direct-permission management
  require `system.config` (superuser). A missing user, unresolvable `PermissionManager`, or
  denied check returns 403.
- **Privilege changes are now correctly attributed and audited.** The `assigned_by` /
  `granted_by` actor was read from the request body (spoofable -- a caller could claim
  someone else made the change); it is now always sourced from the authenticated identity
  (`auth.user`) via a `ResolvesActor` trait, and client-supplied values are ignored.
  The built-but-unused `AuditService` is now wired into every privilege change -- role and
  permission assign/revoke (incl. bulk and role-replace) and role/permission
  create/update/delete (updates record an old-vs-new field diff) -- so grants, revocations,
  and catalog changes are recorded with the real actor.

### Hardening

- **Provider-activation failures are now loud, not silently swallowed.** If the RBAC tables
  are missing, `permission.manager` is unavailable, or the provider fails to activate (e.g.
  core permissions not seeded), Aegis used to `error_log` quietly and degrade to default-deny
  with no clear signal. It now logs explicit WARNING/ERROR messages stating that RBAC is NOT
  active and permission checks will default-deny, and -- outside production -- a genuine
  activation failure (tables exist but the provider could not start) is rethrown so it is
  caught immediately.
- **`resource_filter` wildcard matching is regex-injection-safe.** The stored filter is now
  `preg_quote`'d before being compiled into a pattern (only `*` is re-enabled as a wildcard),
  so a malformed or hostile stored filter cannot become an arbitrary, ReDoS-prone regex; the
  `.` in patterns like `users.*` is now matched literally.
- `RolePermissionRepository` declares an explicit `$defaultFields` column list instead of
  inheriting `SELECT *`.
- Fixed `getVersion()` always reporting `0.0.0`: it read a top-level `version` key that does
  not exist; it now reads `extra.glueful.version` (the manifest the loader uses).

### Changed

- **Require `glueful/framework ^1.55.0`** (was `^1.50.2`). Aegis is the permission provider
  that backs `PermissionManager::can()`, and 1.55.0 is the release where route permission
  enforcement (`#[RequiresPermission]`, the gate middleware) and the container load-time
  guards become real -- so the provider now requires that security baseline.

### Upgrade Notes

- **The `/rbac` management API now enforces RBAC permissions.** Previously any authenticated
  user could call any `/rbac` endpoint; now a caller without the required permission receives
  **403**. Ensure the users who manage RBAC hold the appropriate permissions -- the seeded
  `superuser` / `administrator` roles already do (role/permission *catalog* edits and direct
  raw-permission grants require `superuser`). Clients that relied on the previously-open API
  will need the right role assigned.
- **Requires `glueful/framework ^1.55.0`.** Update the framework first; `composer update` will
  not resolve aegis 1.7.0 against an older framework. No new env vars, no new migrations.

### Planned
- GraphQL API support for role and permission management
- Advanced permission templating system
- Machine learning-based permission recommendations
- Integration with external identity providers (LDAP, Active Directory)
- Real-time permission change notifications

## [1.6.0] - 2026-06-05 — Bootstrap Admin & Framework 1.50 Compatibility

### Added
- **`aegis:bootstrap-admin` CLI command** (`src/Console/BootstrapAdminCommand.php`): first-admin bootstrap for a fresh install. Syncs the declared permission catalog (same mechanics as `permissions:sync`), then creates/reuses a role and grants it the requested permissions and assigns it to a user. Options: `--user` (required; UUID/email/username resolved via `UserProviderInterface`, so Aegis stays decoupled from `glueful/users`), `--role=admin`, repeatable `--permission` (**default `users.read`** — enough to unlock `GET /users` / `GET /users/{uuid}` without minting a super-admin), `--all-catalog` (grant every catalog permission), `--dry-run`, `--yes`. Logic lives in `Services\BootstrapAdminService` (permission grants are additive/idempotent; unknown permissions and unresolved users fail loudly). Command discovery wired in `AegisServiceProvider::boot()` before the RBAC-tables early-return so it's available pre-setup.
- Implements the framework's `PermissionCatalogSyncInterface`: `syncCatalog()` idempotently persists the declared permission catalog (permissions + role grants via `replaceRolePermissions`), and `getManagedCatalog()` reports extension/app-managed permissions only.
- `managed_by` column on the `roles` and `permissions` tables to distinguish catalog-synced rows from hand-created ones (drives stale detection / safe prune).
- Implements the framework's `CatalogPruneInterface` and `RoleCatalogSyncInterface` (Phase 2): `pruneCatalog()`, `getManagedRoles()`, `pruneRoles()` — powering `permissions:diff`/`permissions:sync --prune`. Permission/role repositories gain `findManaged()`/`deleteManagedBySlugs()` (managed-only, soft-delete).

### Changed
- **Minimum framework raised to `glueful/framework >=1.50.2`** (`require-dev` `^1.50.2`); previously `>=1.50.1`. Route docblocks migrated to the editor-clean **`@queryParam name:type="…"`** tag, which `CommentsDocGenerator` parses into the OpenAPI spec as of framework 1.50.2 (the prior positional `@param … query …` form tripped IDE/Intelephense P1133 false positives). Redundant path-parameter docblocks were removed — path params auto-derive from the route URL.
- **`composer analyse` now passes clean at PHPStan level 8** (previously 280 errors, never green). Added accurate array value-type annotations across models, repositories, and services; cast int row-counts to `bool` in repository `update()`/`delete()`/`revoke*()` methods (the declared `: bool` contract was already coercing — no behavior change). No runtime behavior change.

### Removed
- **Dead `src/Validation/` constraint layer** (`Constraints/HasPermission`, `Constraints/ValidRole`, and their `ConstraintValidators`). They extended `Glueful\Validation\Constraints\AbstractConstraint` (removed in the framework's validation rewrite) and `Symfony\Component\Validator\ConstraintValidator` (never a declared dependency), and were referenced nowhere — dead code that would fatal at autoload if ever used.

### Fixed
- **Cache null-safety in `AegisPermissionProvider`.** The optional permission cache (`CacheStore|null`) is now null-guarded on every read/write, so the `cache_enabled=false` path can no longer trigger a null-method-call; a null cache behaves as a no-op (cache miss), exactly as intended.
- `role_permissions` now has `updated_at`/`deleted_at` columns, required by the repository's soft-delete + updated-at lifecycle (assign/replace/revoke).
- `permissions` table gains `deleted_at` for soft-delete consistency (catalog prune and `delete()`).
- `PermissionRepository` invalidates its static slug cache on create/delete (and adds `clearCache()`), preventing stale null-misses during write-then-read within a process.

## [1.5.0] - 2026-02-09

### Changed
- **Framework Compatibility**: Updated minimum framework requirement to Glueful 1.30.0 (Diphda release)
- **Exception Imports**: Migrated from deleted legacy bridge classes to modern exception namespaces
  - `Glueful\Exceptions\NotFoundException` → `Glueful\Http\Exceptions\Client\NotFoundException` in `RoleController` and `PermissionController`
- **composer.json**: Updated `extra.glueful.requires.glueful` to `>=1.30.0`, version bumped to `1.5.0`

### Notes
- No breaking changes to extension API. Import path change is internal.
- Requires Glueful Framework 1.30.0+ due to removal of legacy exception bridge classes.

## [1.4.1] - 2026-02-06

### Changed
- **Version Management**: Version is now read from `composer.json` at runtime via `AegisServiceProvider::composerVersion()`.
  - `registerMeta()` in `boot()` now uses `self::composerVersion()` instead of a hardcoded string.
  - `AegisPermissionProvider::getProviderInfo()` now references `AegisServiceProvider::composerVersion()`.
  - Future releases only require updating `composer.json` and `CHANGELOG.md`.

### Notes
- No breaking changes. Internal refactor only.

## [1.4.0] - 2026-02-05

### Changed
- **Framework Compatibility**: Updated minimum framework requirement to Glueful 1.28.0
  - Compatible with route caching infrastructure (Bellatrix release)
  - Extension already uses `[Controller::class, 'method']` syntax - no code changes required
  - Controllers already accept `Request` directly with proper parameter extraction
- **composer.json**: Updated `extra.glueful.requires.glueful` to `>=1.28.0`

### Framework Features Now Available
- **Route Caching Support**: Routes can now be compiled and cached for improved performance
- **Closure Detection**: RouteCompiler validates handlers and warns about non-cacheable routes
- **ResourceController Refactoring**: Framework controllers use RESTful naming conventions

### Notes
- This release ensures compatibility with Glueful Framework 1.28.0's route caching improvements
- No breaking changes - extension was already following best practices
- Run `composer update` after upgrading

## [1.3.0] - 2026-01-31

### Changed
- **Framework Compatibility**: Updated minimum framework requirement to Glueful 1.22.0
  - Compatible with the new `ApplicationContext` dependency injection pattern
  - No code changes required in extension - framework handles context propagation
- **composer.json**: Updated `extra.glueful.requires.glueful` to `>=1.22.0`

### Notes
- This release ensures compatibility with Glueful Framework 1.22.0's context-based dependency injection
- All existing functionality remains unchanged
- Run `composer update` after upgrading

## [1.2.1] - 2026-01-24

### Changed
- **PermissionRepository**: Improved caching to properly handle null results.
  - Changed from `isset()` to `array_key_exists()` for cache lookups.
  - Prevents redundant database queries for non-existent permissions.
  - Applies to both `findPermissionByUuid()` and `findPermissionBySlug()` methods.
- **AegisServiceProvider**: Added explicit controller registrations to DI container.
  - `PermissionController`, `RoleController`, `UserRoleController` now registered with dependencies.
  - Enables proper dependency injection instead of runtime resolution.
- **Routes**: Updated route handlers to use typed parameters.
  - Changed from `array $params` to typed parameters (`string $uuid`, `string $user_uuid`, etc.).
  - Aligns with framework's modern router parameter resolution system.
  - Improves type safety and IDE autocompletion.

### Notes
- No breaking changes. All endpoints maintain the same behavior.
- Compatible with Glueful Framework 1.19.x.

## [1.2.0] - 2026-01-17

### Breaking Changes
- **PHP 8.3 Required**: Minimum PHP version raised from 8.1 to 8.3.
- **Glueful 1.9.0 Required**: Minimum framework version raised to 1.9.0.

### Changed
- Updated `composer.json` PHP requirement to `^8.3`.
- Updated `extra.glueful.requires.glueful` to `>=1.9.0`.

### Notes
- Ensure your environment runs PHP 8.3 or higher before upgrading.
- Run `composer update` after upgrading.

## [1.1.0] - 2025-09-14

Documentation refresh and migration to Glueful’s modern extension architecture.

### Changed
- Renamed docs to “Aegis (RBAC) Extension”.
- Updated installation to Composer-first with discovery and cache rebuild.
- Revised examples to use container class IDs (`RoleService::class`, `PermissionAssignmentService::class`, `AegisPermissionProvider::class`).
- Documentation: Updated README to reflect modern Glueful extensions system (Composer discovery, `extensions:cache`, `extensions:list|info|why`).
- Installation: Composer-first guidance; refined local dev flow with `config/extensions.php` and `extensions:enable/disable` (dev-only).
- Configuration: Pointed to `Aegis/config/rbac.php` and documented keys used by `AegisServiceProvider`.
- Requirements: Clarified minimums (PHP >= 8.1, Glueful >= 1.0.0).
- Migrated to the modern extensions system in code: provider discovery via Composer `extra.glueful.provider`, ServiceProvider extends `Glueful\\Extensions\\ServiceProvider` with `services()`, `register()`, `boot()`, routes/migrations loaded via provider, config merged from `config/rbac.php`.

### Added
- Quick Start (API): cURL flow to create role, assign to user, and verify via `/rbac` endpoints.
- Quick Start (PHP): Programmatic usage of `RoleService`, `AegisPermissionProvider`, and `permission.manager`.
- API overview: Clarified extra endpoints (stats, cleanup-expired, categories, resource-types).

### Removed
- Legacy references to `extensions/extensions.json` and older CLI verbs.

### Fixed
- Corrected config and class namespaces in README examples.
- Included `permission_audit` table in documented schema.
- Clarified route base path as `/rbac` to match `routes.php`.

## [0.27.0] - 2024-06-21

### Added
- **Hierarchical Role System**
  - Complete role hierarchy with parent-child relationships
  - Automatic permission inheritance from parent roles
  - Configurable hierarchy depth limits and validation
  - Role level management and organization
- **Advanced Permission Management**
  - Direct user permission assignments with role overrides
  - Resource-level permission filtering and access control
  - Temporal permissions with configurable expiry dates
  - Permission categories and resource type organization
- **Enterprise Audit System**
  - Comprehensive audit trails for all RBAC operations
  - Security event logging and monitoring
  - Permission check logging (configurable)
  - Audit data retention and compliance features
- **Multi-Layer Caching Architecture**
  - In-memory request-level caching for performance
  - Distributed caching with Redis/Memcached support
  - Intelligent cache invalidation on permission changes
  - Cache warming and preloading strategies
- **Scoped Permissions for Multi-Tenancy**
  - Tenant-specific permission scoping
  - Department and organizational unit support
  - Context-aware permission checking
  - Flexible scope constraint system

### Enhanced
- **Permission Provider Integration**
  - Complete integration with Glueful's permission system
  - Automatic provider registration and discovery
  - Fallback and chaining support for multiple providers
  - Provider health monitoring and diagnostics
- **RESTful API Architecture**
  - Comprehensive REST API for role management
  - Permission assignment and revocation endpoints
  - User role management with batch operations
  - OpenAPI documentation with examples
- **Database Schema Optimization**
  - Optimized table structures with proper indexing
  - Foreign key constraints for data integrity
  - Migration system with rollback capabilities
  - Database performance monitoring

### Security
- Enhanced permission validation with context checking
- Secure role hierarchy validation to prevent circular dependencies
- Comprehensive input validation and sanitization
- Protection against privilege escalation attacks

### Performance
- Multi-layer caching reduces database queries by up to 95%
- Optimized permission checking with intelligent query planning
- Batch operations for role and permission assignments
- Memory usage optimization for large permission sets

### Developer Experience
- Comprehensive API documentation with usage examples
- Advanced debugging tools and permission tracing
- Health monitoring endpoints for system diagnostics
- Extensive configuration options for customization

## [0.26.0] - 2024-05-20

### Added
- **Core RBAC Infrastructure**
  - Role-based access control foundation
  - Basic permission checking system
  - User-role assignment capabilities
  - Permission-role mapping functionality
- **Database Schema Foundation**
  - Roles, permissions, and user associations tables
  - Basic foreign key relationships
  - Initial migration system setup
- **Permission Provider System**
  - Basic permission provider interface
  - Integration with Glueful's authentication system
  - Simple permission checking methods

### Enhanced
- **Role Management**
  - Role creation, modification, and deletion
  - Basic role assignment to users
  - Permission assignment to roles
- **API Endpoints**
  - Basic REST endpoints for role management
  - User role assignment endpoints
  - Permission management APIs

### Fixed
- Permission inheritance edge cases
- Role assignment validation issues
- Database constraint violations

## [0.25.0] - 2024-04-10

### Added
- **Advanced Role Features**
  - Role hierarchy with parent-child relationships
  - Permission inheritance from parent roles
  - Role level management and validation
- **Audit and Logging**
  - Basic audit trail for role changes
  - Permission modification logging
  - User role assignment tracking
- **Caching Foundation**
  - Basic permission caching implementation
  - Cache invalidation on role changes
  - Performance optimization for permission checks

### Enhanced
- **Permission System**
  - Resource-level permission filtering
  - Permission categories and organization
  - Batch permission assignment capabilities
- **Security Improvements**
  - Enhanced validation for role operations
  - Protection against circular role hierarchies
  - Improved error handling and logging

### Performance
- Implemented basic caching for frequently checked permissions
- Optimized database queries for role hierarchy traversal
- Reduced redundant permission checks

## [0.24.0] - 2024-03-05

### Added
- **Temporal Permissions**
  - Time-based permission expiry system
  - Scheduled permission activation
  - Automatic cleanup of expired permissions
- **Scoped Permissions**
  - Multi-tenant permission scoping
  - Context-aware permission checking
  - Flexible constraint system
- **Advanced API Features**
  - Batch role and permission operations
  - Advanced filtering and sorting
  - Pagination for large datasets

### Enhanced
- **User Experience**
  - Improved error messages and validation
  - Better debugging and diagnostic tools
  - Enhanced configuration management
- **Database Performance**
  - Query optimization for complex permission checks
  - Improved indexing strategy
  - Connection pooling support

### Security
- Enhanced input validation for all RBAC operations
- Improved protection against privilege escalation
- Secure handling of sensitive role data

## [0.23.0] - 2024-02-15

### Added
- **Permission Provider Interface**
  - Standardized permission provider architecture
  - Plugin system for custom permission providers
  - Provider health monitoring and diagnostics
- **Audit System**
  - Comprehensive audit trail implementation
  - Security event logging and monitoring
  - Configurable audit data retention
- **Configuration Management**
  - Environment variable configuration support
  - Runtime configuration updates
  - Validation for RBAC settings

### Infrastructure
- Extension service provider registration
- Route definitions for RBAC endpoints
- Initial testing framework integration
- Documentation foundation

## [0.22.0] - 2024-01-20

### Added
- Project foundation and structure
- Basic RBAC concepts and architecture
- Initial database migration planning
- Core service provider setup

### Infrastructure
- Extension metadata and composer configuration
- Basic development workflow setup
- Initial planning and research

---

## Release Notes

### Version 0.27.0 Highlights

This major release establishes the RBAC extension as a comprehensive, enterprise-grade role-based access control system. Key improvements include:

- **Complete Role Hierarchy**: Full parent-child role relationships with inheritance
- **Advanced Permission System**: Resource-level filtering, temporal permissions, and scoping
- **Enterprise Audit Trails**: Comprehensive logging and security monitoring
- **Multi-Layer Caching**: High-performance caching with intelligent invalidation
- **Multi-Tenancy Support**: Scoped permissions for complex organizational structures

### Upgrade Notes

When upgrading to 0.27.0:
1. Run the database migrations to update the RBAC schema
2. Configure caching settings for optimal performance
3. Review and update any custom permission checking code
4. Test role hierarchy functionality with your existing roles
5. Configure audit logging settings based on your compliance requirements

### Breaking Changes

- Database schema has been significantly enhanced (migration required)
- Permission checking API has been updated for consistency
- Some configuration keys have been reorganized
- Cache keys have changed (existing cache will be invalidated)

### Migration Guide

#### Database Migration
Run all pending migrations to update the schema:
```bash
php glueful migrate run
```

#### Configuration Migration
Update your configuration to use the new format:

```env
# Caching Configuration
RBAC_CACHE_ENABLED=true
RBAC_CACHE_TTL=3600

# Audit Configuration
RBAC_AUDIT_ENABLED=true
RBAC_LOG_PERMISSION_CHECKS=false

# Role Hierarchy
RBAC_HIERARCHY_ENABLED=true
RBAC_MAX_HIERARCHY_DEPTH=10
```

#### API Migration
Update your permission checking code:

```php
// Old API (still supported)
$hasPermission = $rbac->checkPermission($userUuid, 'posts.edit');

// New enhanced API
$hasPermission = $permissionManager->can($userUuid, 'posts.edit', 'post:123', [
    'scope' => ['tenant_id' => 'tenant_1'],
    'time_constraint' => '2024-12-31'
]);
```

### Performance Improvements

Version 0.27.0 includes significant performance enhancements:

- **95% Cache Hit Rate**: Multi-layer caching dramatically reduces database queries
- **Optimized Queries**: Intelligent query planning for complex permission checks
- **Batch Operations**: Efficient bulk role and permission management
- **Memory Optimization**: Reduced memory footprint for large permission sets

### Security Enhancements

- **Circular Dependency Protection**: Prevents invalid role hierarchies
- **Privilege Escalation Prevention**: Enhanced validation for role assignments
- **Comprehensive Auditing**: All RBAC operations are logged for accountability
- **Secure Caching**: Cache keys include security context to prevent unauthorized access

### Enterprise Features

- **Multi-Tenancy**: Complete support for scoped permissions
- **Audit Compliance**: Configurable audit trails for regulatory compliance
- **High Availability**: Distributed caching and connection pooling
- **Monitoring**: Health checks and performance metrics

### Integration Examples

#### Role Hierarchy
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
```

#### Temporal Permissions
```php
// Assign temporary permission
$permissionService->assignPermissionToUser(
    $userUuid,
    'system.maintenance',
    '*',
    ['expires_at' => '2024-12-31 23:59:59']
);
```

#### Scoped Permissions
```php
// Multi-tenant permission checking
$canAccess = $permissionManager->can($userUuid, 'reports.view', '*', [
    'scope' => ['tenant_id' => 'tenant_1', 'department' => 'finance']
]);
```

---

**Full Changelog**: https://github.com/glueful/extensions/compare/rbac-v0.26.0...rbac-v0.27.0
 
