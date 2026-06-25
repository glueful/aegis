<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Events;

use Glueful\Events\Contracts\BaseEvent;

/** A role was revoked from a user (the user_roles pivot row was deleted). */
final class RoleRevokedEvent extends BaseEvent
{
    public function __construct(
        public readonly string $userUuid,
        public readonly string $roleUuid,
    ) {
        parent::__construct();
    }
}
