<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Events;

use Glueful\Events\Contracts\BaseEvent;

/** A role was assigned to a user (the user_roles pivot row was created). */
final class RoleAssignedEvent extends BaseEvent
{
    /** @param array<string,mixed> $options granted_by, expires_at, scope, … */
    public function __construct(
        public readonly string $userUuid,
        public readonly string $roleUuid,
        public readonly array $options = [],
    ) {
        parent::__construct();
    }
}
