<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http;

use Glueful\Auth\UserIdentity;
use Glueful\Bootstrap\ApplicationContext;
use Glueful\Http\Response;
use Glueful\Permissions\PermissionManager;
use Glueful\Routing\RouteMiddleware;
use Symfony\Component\HttpFoundation\Request;

/**
 * Requires the authenticated user to hold a specific RBAC permission.
 *
 * Usage on fluent routes:
 *
 *     $router->post('/roles', [RoleController::class, 'create'])
 *         ->middleware('aegis_permission:roles.create');
 *
 * The required permission slug is the first middleware parameter; an optional second
 * parameter overrides the resource (default `system`). The check runs through the same
 * `PermissionManager::can()` that Aegis itself backs, so an authorized user is allowed and
 * everyone else denied.
 *
 * Fails closed: a missing/empty permission parameter, no authenticated identity, an
 * unresolvable PermissionManager, or a denied check all return 403. Aegis's management API
 * uses this because its routes are fluent (not attribute) routes, so the framework's
 * `gate_permissions` auto-attach (attribute routes only) does not apply.
 */
final class RequirePermission implements RouteMiddleware
{
    public function __construct(private readonly ApplicationContext $context)
    {
    }

    public function handle(Request $request, callable $next, mixed ...$params): mixed
    {
        $permission = isset($params[0]) && is_string($params[0]) ? trim($params[0]) : '';
        if ($permission === '') {
            // A gated route MUST declare its permission; an undeclared gate is a
            // misconfiguration and is treated as deny rather than allow-all.
            return $this->forbidden();
        }

        $user = $request->attributes->get('auth.user');
        if (!$user instanceof UserIdentity) {
            return $this->forbidden();
        }

        $manager = $this->permissionManager();
        if ($manager === null) {
            return $this->forbidden();
        }

        $resource = isset($params[1]) && is_string($params[1]) && trim($params[1]) !== ''
            ? trim($params[1])
            : 'system';

        $tenantId = $this->resolveTenantId($request);

        $context = [
            'roles' => $user->roles(),
            'scopes' => $user->scopes(),
            // The provider's scoped-role matching reads `scope` — a tenant-scoped role
            // assignment only activates when the request's tenant is established here.
            // With no resolvable tenant the scope stays empty, and (fail-closed) only
            // GLOBAL role assignments can satisfy the check.
            'scope' => $tenantId !== null ? ['tenant_id' => $tenantId] : [],
            // Kept at the root too for log/context consumers; the provider does not read it.
            'tenant_id' => $tenantId,
            'route_params' => (array) $request->attributes->get('route.params'),
            'jwt_claims' => (array) $request->attributes->get('jwt.claims'),
        ];

        if (!$manager->can($user->id(), $permission, $resource, $context)) {
            return $this->forbidden();
        }

        return $next($request);
    }

    /**
     * The active tenant for scope matching, resolved from two seams in order:
     *
     * 1. The `tenant.id` request attribute — Aegis's own documented integration point.
     *    Any host or tenancy layer may set it (a string tenant identifier) to activate
     *    scoped-role matching without Aegis knowing that layer's internals.
     * 2. The first-party glueful/tenancy convention: the resolved tenant object stored
     *    in `ApplicationContext` request state under `tenancy.tenant`, read here by KEY
     *    with a duck-typed `uuid` — a soft convention, not a class dependency, so Aegis
     *    still installs without the tenancy extension.
     *
     * Returns null when no tenant is resolvable — scope stays empty and scoped role
     * assignments (correctly) cannot activate.
     */
    private function resolveTenantId(Request $request): ?string
    {
        $attribute = $request->attributes->get('tenant.id');
        if (is_string($attribute) && trim($attribute) !== '') {
            return trim($attribute);
        }

        $tenant = $this->context->getRequestState('tenancy.tenant');
        if (is_object($tenant)) {
            $uuid = $tenant->uuid ?? null;
            if (is_string($uuid) && trim($uuid) !== '') {
                return trim($uuid);
            }
        }

        return null;
    }

    private function permissionManager(): ?PermissionManager
    {
        if (!$this->context->hasContainer()) {
            return null;
        }

        $container = $this->context->getContainer();
        foreach ([PermissionManager::class, 'permission.manager'] as $id) {
            try {
                if ($container->has($id)) {
                    $manager = $container->get($id);
                    if ($manager instanceof PermissionManager) {
                        return $manager;
                    }
                }
            } catch (\Throwable) {
                continue;
            }
        }

        return null;
    }

    private function forbidden(): Response
    {
        return Response::error('Forbidden', Response::HTTP_FORBIDDEN, [
            'code' => 'FORBIDDEN',
        ]);
    }
}
