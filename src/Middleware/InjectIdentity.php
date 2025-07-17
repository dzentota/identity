<?php

namespace Dzentota\Identity\Middleware;

use Dzentota\Identity\Authenticator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Middleware that injects the user identity into the request attributes if authenticated.
 * This middleware does not block unauthenticated users.
 */
class InjectIdentity implements MiddlewareInterface
{
    /**
     * @var Authenticator
     */
    private Authenticator $authenticator;

    /**
     * Create a new inject identity middleware instance.
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
        // Try to get the current identity from the session
        $identity = $this->authenticator->getIdentityFromSession($request);

        // If the user is authenticated, add the identity to the request
        if ($identity) {
            $request = $request->withAttribute(Authenticator::IDENTITY_ATTRIBUTE, $identity);
        }

        // Continue with the request handling pipeline
        return $handler->handle($request);
    }
}
