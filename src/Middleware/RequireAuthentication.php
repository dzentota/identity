<?php

namespace Dzentota\Identity\Middleware;

use Dzentota\Identity\Authenticator;
use Dzentota\Identity\Exception\AuthenticationException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Nyholm\Psr7\Response;

/**
 * Middleware that requires authentication for protected routes.
 * Unauthenticated requests will receive a 401 Unauthorized response.
 */
class RequireAuthentication implements MiddlewareInterface
{
    /**
     * @var Authenticator
     */
    private Authenticator $authenticator;

    /**
     * Create a new authentication required middleware instance.
     *
     * @param Authenticator $authenticator
     */
    public function __construct(Authenticator $authenticator)
    {
        $this->authenticator = $authenticator;
    }

    /**
     * Process an incoming server request.
     *
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // Get the current identity from the session
        $identity = $this->authenticator->getIdentityFromSession($request);

        // If not authenticated, return 401 Unauthorized
        if (!$identity) {
            return new Response(
                401,
                ['Content-Type' => 'application/json'],
                json_encode([
                    'error' => 'Unauthorized',
                    'message' => 'Authentication required to access this resource'
                ])
            );
        }

        // Add the identity to the request attributes
        $request = $request->withAttribute(Authenticator::IDENTITY_ATTRIBUTE, $identity);

        // Continue with the request handling pipeline
        return $handler->handle($request);
    }
}
