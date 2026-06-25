<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Events;

use Glueful\Events\Contracts\BaseEvent;

/** A direct permission was revoked from a user (a user_permissions row was deleted). */
final class PermissionRevokedEvent extends BaseEvent
{
    public function __construct(
        public readonly string $userUuid,
        public readonly string $permissionUuid,
    ) {
        parent::__construct();
    }
}
