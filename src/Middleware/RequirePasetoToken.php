<?php

declare(strict_types=1);

namespace Dzentota\Identity\Middleware;

use Dzentota\Identity\Authenticator;
use Dzentota\Identity\Token\PasetoTokenService;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Requires a valid PASETO Bearer token for protected API routes.
 * Requests without a valid token receive a 401 Unauthorized JSON response.
 *
 * Valid requests have the resolved Identity injected under
 * Authenticator::IDENTITY_ATTRIBUTE, so Authenticator::getIdentity() works
 * regardless of whether session or token auth was used.
 */
class RequirePasetoToken implements MiddlewareInterface
{
    private PasetoTokenService $tokenService;
    private ResponseFactoryInterface $responseFactory;

    public function __construct(PasetoTokenService $tokenService, ResponseFactoryInterface $responseFactory)
    {
        $this->tokenService    = $tokenService;
        $this->responseFactory = $responseFactory;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token    = $this->extractBearerToken($request);
        $identity = $token !== null ? $this->tokenService->verify($token) : null;

        if ($identity === null) {
            $response = $this->responseFactory->createResponse(401)
                ->withHeader('Content-Type', 'application/json');
            $response->getBody()->write((string) json_encode([
                'error'   => 'Unauthorized',
                'message' => 'A valid Bearer token is required to access this resource.',
            ]));
            return $response;
        }

        $request = $request->withAttribute(Authenticator::IDENTITY_ATTRIBUTE, $identity);
        return $handler->handle($request);
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
