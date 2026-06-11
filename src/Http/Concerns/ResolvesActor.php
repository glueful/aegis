<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\Concerns;

use Glueful\Auth\UserIdentity;
use Symfony\Component\HttpFoundation\Request;

/**
 * Resolves the acting user (the "who did this") for audit/attribution fields.
 *
 * The actor MUST come from the authenticated identity (`auth.user`), never from the request
 * body. Reading `assigned_by`/`granted_by` from client input lets a caller forge the audit
 * trail (claim someone else made the change). This trait is the single source of truth.
 */
trait ResolvesActor
{
    /**
     * The authenticated actor's uuid, or null if unauthenticated. Request-body fields like
     * `assigned_by` / `granted_by` are deliberately ignored.
     */
    protected function actorUuid(Request $request): ?string
    {
        $user = $request->attributes->get('auth.user');

        return $user instanceof UserIdentity ? $user->id() : null;
    }
}
