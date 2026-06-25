<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Events;

use Glueful\Events\Contracts\BaseEvent;

/** A permission was attached to a role (a role_permissions pivot row was created). */
final class RolePermissionAssignedEvent extends BaseEvent
{
    /** @param array<string,mixed> $options resource_filter, constraints, granted_by, expires_at, … */
    public function __construct(
        public readonly string $roleUuid,
        public readonly string $permissionUuid,
        public readonly array $options = [],
    ) {
        parent::__construct();
    }
}
