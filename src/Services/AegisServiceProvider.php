<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Services;

use Glueful\Extensions\ServiceProvider;
use Glueful\Extensions\Aegis\AegisPermissionProvider;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;
use Glueful\Extensions\Aegis\Repositories\UserPermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RolePermissionRepository;
use Glueful\Extensions\Aegis\Services\RoleService;
use Glueful\Extensions\Aegis\Services\PermissionAssignmentService;
use Glueful\Extensions\Aegis\Services\AuditService;

class AegisServiceProvider extends ServiceProvider
{
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
            AuditService::class => ['class' => AuditService::class, 'shared' => true],

            AegisPermissionProvider::class => ['class' => AegisPermissionProvider::class, 'shared' => true],
        ];
    }

    public function register(): void
    {
        $this->mergeConfig('rbac', require __DIR__ . '/../../config/rbac.php');
    }

    public function boot(): void
    {
        // 1) Register metadata first so CLI diagnostics always work
        try {
            $this->app->get(\Glueful\Extensions\ExtensionManager::class)->registerMeta(self::class, [
                'slug' => 'aegis',
                'name' => 'Aegis',
                'version' => '1.1.3',
                'description' => 'Modern, hierarchical role-based access control system',
            ]);
        } catch (\Throwable $e) {
            error_log('[Aegis] metadata registration failed: ' . $e->getMessage());
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

        // 3) Register migrations directory (low risk)
        try {
            $this->loadMigrationsFrom(dirname(__DIR__, 2) . '/migrations');
        } catch (\Throwable $e) {
            error_log('[Aegis] Failed to register migrations: ' . $e->getMessage());
        }

        // Permission provider wiring only if RBAC tables exist
        try {
            if (!$this->tablesExist()) {
                return;
            }

            $provider = $this->app->get(AegisPermissionProvider::class);
            $config = config('rbac', []);
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
