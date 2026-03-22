<?php

declare(strict_types=1);

namespace Dzentota\Identity\Middleware;

use Dzentota\Identity\Authenticator;
use Dzentota\Identity\Token\PasetoTokenService;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Reads a PASETO Bearer token from the Authorization header and, if valid,
 * injects the resolved Identity into the request attributes.
 *
 * Unauthenticated requests are passed through unchanged — use RequirePasetoToken
 * to block them instead.
 *
 * The identity is stored under Authenticator::IDENTITY_ATTRIBUTE, so
 * Authenticator::getIdentity() works regardless of whether session or token
 * auth was used.
 */
class InjectPasetoIdentity implements MiddlewareInterface
{
    private PasetoTokenService $tokenService;

    public function __construct(PasetoTokenService $tokenService)
    {
        $this->tokenService = $tokenService;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $identity = $this->resolveIdentity($request);

        if ($identity !== null) {
            $request = $request->withAttribute(Authenticator::IDENTITY_ATTRIBUTE, $identity);
        }

        return $handler->handle($request);
    }

    private function resolveIdentity(ServerRequestInterface $request): ?\Dzentota\Identity\Identity
    {
        $token = $this->extractBearerToken($request);
        if ($token === null) {
            return null;
        }

        return $this->tokenService->verify($token);
    }

    private function extractBearerToken(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine('Authorization');
        if (strncasecmp($header, 'Bearer ', 7) !== 0) {
            return null;
        }
        $token = trim(substr($header, 7));
        return $token !== '' ? $token : null;
    }
}
