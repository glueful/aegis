<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Tests\Unit;

use Glueful\Auth\UserIdentity;
use Glueful\Bootstrap\ApplicationContext;
use Glueful\Extensions\Aegis\Http\RequirePermission;
use Glueful\Permissions\PermissionManager;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The RBAC management routes are gated by this middleware. It must fail closed: a missing
 * permission parameter, no authenticated identity, an unresolvable PermissionManager, or a
 * denied check all return 403. Only an explicitly-granted check passes through.
 */
final class RequirePermissionTest extends TestCase
{
    private function middleware(?PermissionManager $manager, ?ApplicationContext $context = null): RequirePermission
    {
        $container = new class ($manager) implements ContainerInterface {
            public function __construct(private ?PermissionManager $manager)
            {
            }
            public function has(string $id): bool
            {
                return $this->manager !== null
                    && in_array($id, [PermissionManager::class, 'permission.manager'], true);
            }
            public function get(string $id): mixed
            {
                if ($this->has($id)) {
                    return $this->manager;
                }
                throw new class ('not found') extends \RuntimeException implements NotFoundExceptionInterface {
                };
            }
        };

        $context ??= new ApplicationContext(sys_get_temp_dir());
        $context->setContainer($container);

        return new RequirePermission($context);
    }

    private function request(?UserIdentity $user): Request
    {
        $request = Request::create('/x');
        if ($user !== null) {
            $request->attributes->set('auth.user', $user);
        }
        return $request;
    }

    private function next(): callable
    {
        return static fn(Request $r): Response => new Response('OK', 200);
    }

    public function test_missing_permission_param_is_denied(): void
    {
        $manager = $this->createMock(PermissionManager::class);
        $manager->method('can')->willReturn(true);

        $result = $this->middleware($manager)
            ->handle($this->request(new UserIdentity('u1', ['administrator'])), $this->next());

        self::assertSame(403, $result->getStatusCode());
    }

    public function test_no_authenticated_user_is_denied(): void
    {
        $manager = $this->createMock(PermissionManager::class);
        $manager->method('can')->willReturn(true);

        $result = $this->middleware($manager)
            ->handle($this->request(null), $this->next(), 'roles.assign');

        self::assertSame(403, $result->getStatusCode());
    }

    public function test_no_permission_manager_is_denied(): void
    {
        $result = $this->middleware(null)
            ->handle($this->request(new UserIdentity('u1', ['administrator'])), $this->next(), 'roles.assign');

        self::assertSame(403, $result->getStatusCode());
    }

    public function test_denied_permission_returns_403(): void
    {
        $manager = $this->createMock(PermissionManager::class);
        $manager->method('can')->willReturn(false);

        $result = $this->middleware($manager)
            ->handle($this->request(new UserIdentity('plain-user', ['user'])), $this->next(), 'roles.assign');

        self::assertSame(403, $result->getStatusCode());
    }

    public function test_granted_permission_passes_through(): void
    {
        $manager = $this->createMock(PermissionManager::class);
        $manager->expects(self::once())
            ->method('can')
            ->with('admin-1', 'roles.assign', 'system', self::anything())
            ->willReturn(true);

        $result = $this->middleware($manager)
            ->handle($this->request(new UserIdentity('admin-1', ['administrator'])), $this->next(), 'roles.assign');

        self::assertSame(200, $result->getStatusCode());
        self::assertSame('OK', $result->getContent());
    }

    /**
     * Captures the context array the middleware hands to PermissionManager::can().
     *
     * @param array<string, mixed> $captured
     */
    private function capturingManager(array &$captured): PermissionManager
    {
        $manager = $this->createMock(PermissionManager::class);
        $manager->method('can')->willReturnCallback(
            function (string $userUuid, string $permission, string $resource, array $context) use (&$captured): bool {
                $captured = $context;
                return true;
            }
        );
        return $manager;
    }

    // The provider's scoped-role matching reads context['scope']; the middleware previously
    // put tenant_id only at the context ROOT (never read) and sourced it from a `tenant.id`
    // attribute nothing populates — so scoped-role filtering never activated through this
    // middleware. These pin the repaired wiring.
    public function test_tenant_attribute_feeds_the_scope_context(): void
    {
        $captured = [];
        $request = $this->request(new UserIdentity('admin-1', ['administrator']));
        $request->attributes->set('tenant.id', 'tenant-a');

        $this->middleware($this->capturingManager($captured))
            ->handle($request, $this->next(), 'roles.assign');

        self::assertSame(['tenant_id' => 'tenant-a'], $captured['scope']);
        self::assertSame('tenant-a', $captured['tenant_id']);
    }

    public function test_tenancy_request_state_feeds_the_scope_context(): void
    {
        $captured = [];
        $context = new ApplicationContext(sys_get_temp_dir());
        // Duck-typed stand-in for glueful/tenancy's Tenant model stored under its
        // requestState key — Aegis reads only the `uuid` property, never the class.
        $context->setRequestState('tenancy.tenant', new class {
            public string $uuid = 'tenant-b';
        });

        $this->middleware($this->capturingManager($captured), $context)
            ->handle($this->request(new UserIdentity('admin-1', ['administrator'])), $this->next(), 'roles.assign');

        self::assertSame(['tenant_id' => 'tenant-b'], $captured['scope']);
    }

    public function test_the_tenant_attribute_wins_over_request_state(): void
    {
        $captured = [];
        $context = new ApplicationContext(sys_get_temp_dir());
        $context->setRequestState('tenancy.tenant', new class {
            public string $uuid = 'tenant-b';
        });
        $request = $this->request(new UserIdentity('admin-1', ['administrator']));
        $request->attributes->set('tenant.id', 'tenant-a');

        $this->middleware($this->capturingManager($captured), $context)
            ->handle($request, $this->next(), 'roles.assign');

        self::assertSame(['tenant_id' => 'tenant-a'], $captured['scope']);
    }

    public function test_no_resolvable_tenant_leaves_the_scope_empty(): void
    {
        $captured = [];

        $this->middleware($this->capturingManager($captured))
            ->handle($this->request(new UserIdentity('admin-1', ['administrator'])), $this->next(), 'roles.assign');

        self::assertSame([], $captured['scope']);
        self::assertNull($captured['tenant_id']);
    }
}
