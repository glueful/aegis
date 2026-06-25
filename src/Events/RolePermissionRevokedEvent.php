<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Events;

use Glueful\Events\Contracts\BaseEvent;

/** A permission was detached from a role (a role_permissions pivot row was deleted). */
final class RolePermissionRevokedEvent extends BaseEvent
{
    public function __construct(
        public readonly string $roleUuid,
        public readonly string $permissionUuid,
    ) {
        parent::__construct();
    }
}
