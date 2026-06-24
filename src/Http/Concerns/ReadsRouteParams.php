<?php

declare(strict_types=1);

namespace Glueful\Extensions\Aegis\Http\Concerns;

use Symfony\Component\HttpFoundation\Request;

/**
 * Reads matched route parameters from a request.
 *
 * The framework router stores matched params under the `_route_params` attribute (and injects them
 * as handler method arguments by name). It does NOT expose each param as its own top-level request
 * attribute, so `$request->attributes->get('uuid')` is always empty and every `/{uuid}` route would
 * 404 ("not found"). This helper pulls from the place the router actually populates.
 */
trait ReadsRouteParams
{
    protected function routeParam(Request $request, string $name, string $default = ''): string
    {
        $params = $request->attributes->get('_route_params');
        if (is_array($params) && isset($params[$name]) && is_scalar($params[$name])) {
            return (string) $params[$name];
        }
        return $default;
    }
}
