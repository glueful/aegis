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
            $provider->initialize($providerConfig);

            if ($this->app->has('permission.manager')) {
                $manager = $this->app->get('permission.manager');
                $manager->registerProviders(['rbac' => $provider]);
                $manager->setProvider($provider, $providerConfig);
            }
        } catch (\Exception $e) {
            error_log('Aegis: Failed to initialize permission provider: ' . $e->getMessage());
        }

        $this->loadRoutesFrom(__DIR__ . '/../routes.php');
        $this->loadMigrationsFrom(dirname(__DIR__, 2) . '/migrations');
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
