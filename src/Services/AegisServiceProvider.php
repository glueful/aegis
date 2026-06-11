<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Services;

use Glueful\Bootstrap\ApplicationContext;
use Glueful\Database\Migrations\MigrationPriority;
use Glueful\Extensions\ServiceProvider;
use Glueful\Extensions\Aegis\AegisPermissionProvider;
use Glueful\Extensions\Aegis\IdentityClaimsProvider;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;
use Glueful\Extensions\Aegis\Repositories\UserPermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RolePermissionRepository;
use Glueful\Extensions\Aegis\Services\RoleService;
use Glueful\Extensions\Aegis\Services\PermissionAssignmentService;
use Glueful\Extensions\Aegis\Services\AuditService;
use Glueful\Extensions\Aegis\Controllers\PermissionController;
use Glueful\Extensions\Aegis\Controllers\RoleController;
use Glueful\Extensions\Aegis\Controllers\UserRoleController;

class AegisServiceProvider extends ServiceProvider
{
    private static ?string $cachedVersion = null;

    /**
     * Read the extension version from composer.json (cached)
     */
    public static function composerVersion(): string
    {
        if (self::$cachedVersion === null) {
            $path = __DIR__ . '/../../composer.json';
            $contents = file_get_contents($path);
            $composer = $contents !== false ? json_decode($contents, true) : null;
            self::$cachedVersion = (is_array($composer) ? ($composer['version'] ?? null) : null) ?? '0.0.0';
        }

        return self::$cachedVersion;
    }

    public static function services(): array
    {
        return [
            RoleRepository::class => ['class' => RoleRepository::class, 'shared' => true],
            PermissionRepository::class => ['class' => PermissionRepository::class, 'shared' => true],
            UserRoleRepository::class => ['class' => UserRoleRepository::class, 'shared' => true],
            UserPermissionRepository::class => ['class' => UserPermissionRepository::class, 'shared' => true],
            RolePermissionRepository::class => ['class' => RolePermissionRepository::class, 'shared' => true],

            RoleService::class => [
                'class' => RoleService::class,
                'shared' => true,
                'arguments' => ['@' . RoleRepository::class, '@' . UserRoleRepository::class],
            ],
            PermissionAssignmentService::class => [
                'class' => PermissionAssignmentService::class,
                'shared' => true,
                'arguments' => [
                    '@' . PermissionRepository::class,
                    '@' . UserPermissionRepository::class,
                    '@' . RoleRepository::class,
                    '@' . UserRoleRepository::class,
                    '@' . RolePermissionRepository::class,
                ],
            ],
            AuditService::class => ['class' => AuditService::class, 'shared' => true, 'autowire' => true],

            // RBAC permission gate for the (fluent) management routes. Aliased 'aegis_permission'
            // so routes can require a specific permission via ->middleware('aegis_permission:<slug>').
            \Glueful\Extensions\Aegis\Http\RequirePermission::class => [
                'class' => \Glueful\Extensions\Aegis\Http\RequirePermission::class,
                'shared' => true,
                'autowire' => true,
                'alias' => ['aegis_permission'],
            ],

            AegisPermissionProvider::class => ['class' => AegisPermissionProvider::class, 'shared' => true, 'autowire' => true],

            // Folds Aegis role claims into the authenticated identity post-auth. Tagged
            // 'identity.claims_provider' so core's IdentityResolver collects + invokes it (same
            // mechanism as console.commands). Needs UserRoleRepository injected.
            IdentityClaimsProvider::class => [
                'class' => IdentityClaimsProvider::class,
                'shared' => true,
                'arguments' => ['@' . UserRoleRepository::class],
                'tags' => ['identity.claims_provider'],
            ],

            // Controllers
            PermissionController::class => [
                'class' => PermissionController::class,
                'shared' => true,
                'arguments' => [
                    '@' . PermissionAssignmentService::class,
                    '@' . PermissionRepository::class,
                    '@' . UserPermissionRepository::class,
                    '@' . AuditService::class,
                ],
            ],
            RoleController::class => [
                'class' => RoleController::class,
                'shared' => true,
                'arguments' => [
                    '@' . RoleService::class,
                    '@' . RoleRepository::class,
                    '@' . AuditService::class,
                ],
            ],
            UserRoleController::class => [
                'class' => UserRoleController::class,
                'shared' => true,
                'arguments' => [
                    '@' . RoleService::class,
                    '@' . PermissionAssignmentService::class,
                    '@' . UserRoleRepository::class,
                    '@' . AuditService::class,
                ],
            ],
        ];
    }

    public function register(ApplicationContext $context): void
    {
        $this->mergeConfig('rbac', require __DIR__ . '/../../config/rbac.php');
    }

    public function boot(ApplicationContext $context): void
    {
        // 1) Register metadata first so CLI diagnostics always work
        try {
            $this->app->get(\Glueful\Extensions\ExtensionManager::class)->registerMeta(self::class, [
                'slug' => 'aegis',
                'name' => 'Aegis',
                'version' => self::composerVersion(),
                'description' => 'Modern, hierarchical role-based access control system',
            ]);
        } catch (\Throwable $e) {
            error_log('[Aegis] metadata registration failed: ' . $e->getMessage());
        }

        // 1.5) Discover CLI commands (e.g. aegis:bootstrap-admin) before any early-return below —
        //      the bootstrap command is run precisely when RBAC isn't fully set up yet.
        try {
            $this->discoverCommands('Glueful\\Extensions\\Aegis\\Console', __DIR__ . '/../Console');
        } catch (\Throwable $e) {
            error_log('[Aegis] command discovery failed: ' . $e->getMessage());
        }

        // 2) Load routes (executes file) — guard to avoid aborting boot
        try {
            $this->loadRoutesFrom(__DIR__ . '/../routes.php');
        } catch (\Throwable $e) {
            error_log('[Aegis] Failed to load routes: ' . $e->getMessage());
            $env = (string)($_ENV['APP_ENV'] ?? (getenv('APP_ENV') !== false ? getenv('APP_ENV') : 'production'));
            if ($env !== 'production') {
                throw $e; // fail fast in non-production
            }
        }

        // 3) Register migrations directory (low risk). DEPENDENT priority orders Aegis after
        //    glueful/users (IDENTITY) and the app (DEFAULT); source records 'glueful/aegis'.
        try {
            $this->loadMigrationsFrom(
                dirname(__DIR__, 2) . '/migrations',
                MigrationPriority::DEPENDENT,
                'glueful/aegis'
            );
        } catch (\Throwable $e) {
            error_log('[Aegis] Failed to register migrations: ' . $e->getMessage());
        }

        // Permission provider wiring only if RBAC tables exist
        try {
            if (!$this->tablesExist()) {
                return;
            }

            $provider = $this->app->get(AegisPermissionProvider::class);
            $config = config($context, 'rbac', []);
            $providerConfig = [
                'cache_enabled' => $config['permissions']['cache_enabled'] ?? true,
                'cache_ttl' => $config['permissions']['cache_ttl'] ?? 3600,
                'cache_prefix' => $config['permissions']['cache_prefix'] ?? 'rbac:',
                'enable_hierarchy' => $config['roles']['inherit_permissions'] ?? true,
                'enable_inheritance' => $config['permissions']['inheritance_enabled'] ?? true,
                'max_hierarchy_depth' => $config['roles']['max_hierarchy_depth'] ?? 10,
            ];

            if ($this->app->has('permission.manager')) {
                $manager = $this->app->get('permission.manager');
                $manager->registerProviders(['rbac' => $provider]);
                $manager->setProvider($provider, $providerConfig);
            } else {
                // Guard: log and defer when permission manager is not yet available
                error_log('[Aegis] permission.manager not available during boot; deferring provider setup');
            }
        } catch (\Exception $e) {
            error_log('Aegis: Failed to initialize permission provider: ' . $e->getMessage());
        }
    }

    private function tablesExist(): bool
    {
        try {
            $connection = new \Glueful\Database\Connection();
            $schema = $connection->getSchemaBuilder();
            return $schema->hasTable('roles') && $schema->hasTable('permissions') && $schema->hasTable('role_permissions');
        } catch (\Exception $e) {
            return false;
        }
    }
}
