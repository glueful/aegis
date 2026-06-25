<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Events;

use Glueful\Events\Contracts\BaseEvent;

/**
 * A direct permission was granted to a user (a user_permissions row was created).
 *
 * Aegis stores scope as a JSON `resource_filter` column — there is no `resource`
 * positional. The decoded resource_filter (plus granted_by / expires_at) travels
 * in $options.
 */
final class PermissionAssignedEvent extends BaseEvent
{
    /** @param array<string,mixed> $options resource_filter, granted_by, expires_at, … */
    public function __construct(
        public readonly string $userUuid,
        public readonly string $permissionUuid,
        public readonly array $options = [],
    ) {
        parent::__construct();
    }
}
