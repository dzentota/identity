<?php

namespace Dzentota\Identity\Tests\Middleware;

use Dzentota\Identity\Authenticator;
use Dzentota\Identity\Middleware\RequireAuthentication;
use Dzentota\Identity\Tests\Mocks\MockCredentialStore;
use Dzentota\Identity\Tests\Mocks\MockSessionManager;
use Dzentota\Session\SessionManager;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class RequireAuthenticationTest extends TestCase
{
    private Authenticator $authenticator;
    private MockCredentialStore $credentialStore;
    private SessionManager $sessionManager;
    private RequireAuthentication $middleware;

    protected function setUp(): void
    {
        MockSessionManager::reset();
        $this->credentialStore = new MockCredentialStore();
        $this->sessionManager = MockSessionManager::create();
        $this->authenticator = new Authenticator(
            $this->credentialStore,
            $this->sessionManager
        );
        $this->middleware = new RequireAuthentication($this->authenticator);
    }

    protected function tearDown(): void
    {
        \Mockery::close();
    }

    public function testProcessWithAuthenticatedUser(): void
    {
        $request = new ServerRequest('GET', '/protected');

        // Simulate authenticated user
        $this->sessionManager->set(Authenticator::AUTH_USER_ID, 'user123');
        $this->sessionManager->set(Authenticator::AUTH_TIME, time());

        // Mock handler that will be called if authentication succeeds
        $handler = new class() implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200, [], 'Protected resource');
            }
        };

        $response = $this->middleware->process($request, $handler);

        // Should have 200 status code since the user is authenticated
        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testProcessWithUnauthenticatedUser(): void
    {
        $request = new ServerRequest('GET', '/protected');

        // No session data means unauthenticated

        // This handler should not be called
        $handler = new class() implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200, [], 'Should not reach this point');
            }
        };

        $response = $this->middleware->process($request, $handler);

        // Should have 401 status code since the user is not authenticated
        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testRequestAttributeContainsIdentity(): void
    {
        $request = new ServerRequest('GET', '/protected');

        // Simulate authenticated user
        $this->sessionManager->set(Authenticator::AUTH_USER_ID, 'user123');
        $this->sessionManager->set(Authenticator::AUTH_TIME, time());

        // Mock handler that will check for the identity attribute
        $handler = new class() implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $identity = $request->getAttribute('identity');
                return new Response(200, [], $identity ? $identity->getId() : 'No identity');
            }
        };

        $response = $this->middleware->process($request, $handler);

        // Response body should contain the user ID since identity was injected
        $this->assertEquals('user123', (string)$response->getBody());
    }
}
