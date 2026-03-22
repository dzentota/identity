<?php

namespace Dzentota\Identity\Middleware;

use Dzentota\Identity\Authenticator;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Middleware that requires authentication for protected routes.
 * Unauthenticated requests receive a 401 Unauthorized response.
 */
class RequireAuthentication implements MiddlewareInterface
{
    private Authenticator $authenticator;
    private ResponseFactoryInterface $responseFactory;

    public function __construct(Authenticator $authenticator, ResponseFactoryInterface $responseFactory)
    {
        $this->authenticator = $authenticator;
        $this->responseFactory = $responseFactory;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $identity = $this->authenticator->getCurrentIdentity($request);

        if (!$identity) {
            $response = $this->responseFactory->createResponse(401)
                ->withHeader('Content-Type', 'application/json');
            $response->getBody()->write((string) json_encode([
                'error'   => 'Unauthorized',
                'message' => 'Authentication required to access this resource',
            ]));
            return $response;
        }

        $request = $request->withAttribute(Authenticator::IDENTITY_ATTRIBUTE, $identity);
        return $handler->handle($request);
    }
}
