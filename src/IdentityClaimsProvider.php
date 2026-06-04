<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis;

use Glueful\Auth\Contracts\IdentityClaimsProviderInterface;
use Glueful\Auth\UserIdentity;
use Glueful\Extensions\Aegis\Repositories\UserRoleRepository;

/**
 * Folds Aegis role claims into an authenticated identity. Core's IdentityResolver invokes every
 * service tagged `identity.claims_provider` after credential verification, so login stays
 * provider-agnostic: Aegis owns roles, the user store owns identity, and they never own the same
 * fact (design §1).
 *
 * The identity uuid is treated as an external principal id (no FK) — membership is read from
 * user_roles, never fabricated.
 */
final class IdentityClaimsProvider implements IdentityClaimsProviderInterface
{
    public function __construct(private UserRoleRepository $userRoles)
    {
    }

    public function enrich(UserIdentity $identity): UserIdentity
    {
        $roleSlugs = $this->userRoles->roleSlugsForUser($identity->uuid());
        if ($roleSlugs === []) {
            return $identity; // never fabricate membership
        }

        // Additive: union with any roles already present (IdentityResolver also enforces this).
        return $identity->withClaims([
            'roles' => array_values(array_unique([...$identity->roles(), ...$roleSlugs])),
        ]);
    }
}
