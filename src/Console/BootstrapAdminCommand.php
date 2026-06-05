<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Console;

use Glueful\Auth\Contracts\UserProviderInterface;
use Glueful\Console\BaseCommand;
use Glueful\Extensions\Aegis\AegisPermissionProvider;
use Glueful\Extensions\Aegis\Repositories\PermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RolePermissionRepository;
use Glueful\Extensions\Aegis\Repositories\RoleRepository;
use Glueful\Extensions\Aegis\Services\BootstrapAdminResult;
use Glueful\Extensions\Aegis\Services\BootstrapAdminService;
use Glueful\Extensions\ExtensionManager;
use Glueful\Interfaces\Permission\PermissionCatalogSyncInterface;
use Glueful\Permissions\Catalog\PermissionRegistry;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * First-admin bootstrap: sync the declared permission catalog (so e.g. `users.read` exists),
 * then grant a role to a user. By default it grants only `users.read` — enough to unlock
 * GET /users and GET /users/{uuid} — NOT every permission. Use --all-catalog for a full admin.
 */
#[AsCommand(
    name: 'aegis:bootstrap-admin',
    description: 'Sync the permission catalog and grant a role (default: users.read) to a user'
)]
final class BootstrapAdminCommand extends BaseCommand
{
    protected function configure(): void
    {
        $this
            ->addOption('user', null, InputOption::VALUE_REQUIRED, 'User UUID, email, or username (resolved via UserProviderInterface)')
            ->addOption('role', null, InputOption::VALUE_REQUIRED, 'Role slug to create or reuse', 'admin')
            ->addOption('permission', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Permission slug to grant (repeatable; default: users.read)', [])
            ->addOption('all-catalog', null, InputOption::VALUE_NONE, 'Grant every synced catalog permission to the role (full admin)')
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Show what would happen without writing')
            ->addOption('yes', 'y', InputOption::VALUE_NONE, 'Assume yes — non-interactive (for scripts)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $userId = trim((string) ($input->getOption('user') ?? ''));
        if ($userId === '') {
            $output->writeln('<error>--user is required (UUID, email, or username).</error>');
            return self::FAILURE;
        }
        $roleSlug = (string) ($input->getOption('role') ?: 'admin');
        $dryRun = (bool) $input->getOption('dry-run');

        // 1) Sync the catalog programmatically (same mechanics as `permissions:sync`) so the
        //    declared permissions (e.g. users.read) exist before we grant them.
        $provider = $this->syncCatalog($output);
        if ($provider === null) {
            $output->writeln(
                '<error>No persistent RBAC provider with catalog sync is active. '
                . 'Enable glueful/aegis and run migrations first.</error>'
            );
            return self::FAILURE;
        }

        /** @var PermissionRegistry $registry */
        $registry = $this->getService(PermissionRegistry::class);
        /** @var list<string> $explicit */
        $explicit = array_values((array) $input->getOption('permission'));
        $permissions = BootstrapAdminService::resolvePermissions(
            $explicit,
            (bool) $input->getOption('all-catalog'),
            $registry->permissionSlugs()
        );

        // 2) Bootstrap: resolve user, create/reuse role, additively grant, assign role.
        $service = new BootstrapAdminService(
            $this->getService(UserProviderInterface::class),
            new RoleRepository(),
            new PermissionRepository(),
            new RolePermissionRepository(),
            $provider,
        );

        try {
            $result = $service->bootstrap($userId, $roleSlug, $permissions, $dryRun);
        } catch (\Throwable $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');
            return self::FAILURE;
        }

        $this->report($output, $result);
        return self::SUCCESS;
    }

    /** Rebuild + persist the catalog; return the active sync-capable Aegis provider, or null. */
    private function syncCatalog(OutputInterface $output): ?AegisPermissionProvider
    {
        /** @var ExtensionManager $extensions */
        $extensions = $this->getService(ExtensionManager::class);
        $extensions->discover();
        $extensions->aggregatePermissionCatalog();

        if (!$this->getContainer()->has('permission.manager')) {
            return null;
        }
        $active = $this->getContainer()->get('permission.manager')->getProvider();
        if (!$active instanceof AegisPermissionProvider || !$active instanceof PermissionCatalogSyncInterface) {
            return null;
        }

        /** @var PermissionRegistry $registry */
        $registry = $this->getService(PermissionRegistry::class);
        $permissions = array_map(static fn($p) => $p->toArray(), $registry->permissions());
        $roles = array_map(static fn($r) => $r->toArray(), $registry->roles());
        $sync = $active->syncCatalog($permissions, $roles);

        $output->writeln(sprintf(
            '<info>Catalog synced</info> — created: %d, updated: %d, unchanged: %d',
            $sync->created,
            $sync->updated,
            $sync->unchanged
        ));

        return $active;
    }

    private function report(OutputInterface $output, BootstrapAdminResult $result): void
    {
        if ($result->dryRun) {
            $output->writeln('<comment>[dry-run] no changes written.</comment>');
            $output->writeln(sprintf('Would %s role <info>%s</info>', $result->roleCreated ? 'create' : 'reuse', $result->roleSlug));
            $output->writeln('Would grant: ' . implode(', ', $result->requested));
            $output->writeln(sprintf('Would assign role <info>%s</info> to user <info>%s</info>', $result->roleSlug, $result->userUuid));
            return;
        }

        $output->writeln(sprintf('Role <info>%s</info>: %s', $result->roleSlug, $result->roleCreated ? 'created' : 'reused'));
        $output->writeln('Granted permissions: ' . ($result->granted === [] ? '(already present)' : implode(', ', $result->granted)));
        $output->writeln(sprintf('Assigned role <info>%s</info> to user <info>%s</info>', $result->roleSlug, $result->userUuid));
    }
}
