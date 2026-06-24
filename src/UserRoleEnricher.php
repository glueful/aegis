<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis;

use Glueful\Auth\Contracts\UserRecordEnricherInterface;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;

/**
 * Attaches each user's `roles` to user records the identity store is about to return.
 *
 * Registered under the core `users.record_enricher` tag (see {@see UserRecordEnricherInterface}),
 * so glueful/users surfaces roles on its `/users`, `/users/{uuid}` and `/me` payloads without ever
 * depending on Aegis. Symmetric to {@see IdentityClaimsProvider}, which folds roles into the
 * authenticated identity at login — this folds them into arbitrary read batches. One batched query.
 */
final class UserRoleEnricher implements UserRecordEnricherInterface
{
    public function __construct(private UserRoleRepository $userRoles)
    {
    }

    /**
     * @param list<string> $userUuids
     * @return array<string, array<string, mixed>>
     */
    public function enrich(array $userUuids): array
    {
        $out = [];
        foreach ($this->userRoles->getRolesForUsers($userUuids) as $userUuid => $roles) {
            $out[$userUuid] = ['roles' => $roles];
        }
        return $out;
    }
}
