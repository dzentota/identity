<?php

namespace Dzentota\Identity\Tests\Middleware;

use Dzentota\Identity\Authenticator;
use Dzentota\Identity\Middleware\InjectIdentity;
use Dzentota\Identity\Tests\Mocks\MockCredentialStore;
use Dzentota\Identity\Tests\Mocks\MockSessionManager;
use Dzentota\Session\SessionManager;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class InjectIdentityTest extends TestCase
{
    private Authenticator $authenticator;
    private MockCredentialStore $credentialStore;
    private SessionManager $sessionManager;
    private InjectIdentity $middleware;

    protected function setUp(): void
    {
        MockSessionManager::reset();
        $this->credentialStore = new MockCredentialStore();
        $this->sessionManager = MockSessionManager::create();
        $this->authenticator = new Authenticator(
            $this->credentialStore,
            $this->sessionManager
        );
        $this->middleware = new InjectIdentity($this->authenticator);
    }

    protected function tearDown(): void
    {
        \Mockery::close();
    }

    public function testProcessWithAuthenticatedUser(): void
    {
        $request = new ServerRequest('GET', '/page');

        // Simulate authenticated user
        $this->sessionManager->set(Authenticator::AUTH_USER_ID, 'user123');
        $this->sessionManager->set(Authenticator::AUTH_TIME, time());

        // Mock handler that will check for the identity attribute
        $handler = new class() implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $identity = $request->getAttribute('identity');
                return new Response(200, [], $identity ? 'authenticated' : 'anonymous');
            }
        };

        $response = $this->middleware->process($request, $handler);

        // Response should indicate the user is authenticated
        $this->assertEquals('authenticated', (string)$response->getBody());
    }

    public function testProcessWithUnauthenticatedUser(): void
    {
        $request = new ServerRequest('GET', '/page');

        // No session data means unauthenticated

        // Mock handler that should still be called for anonymous users
        $handler = new class() implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $identity = $request->getAttribute('identity');
                return new Response(200, [], $identity ? 'authenticated' : 'anonymous');
            }
        };

        $response = $this->middleware->process($request, $handler);

        // Response should indicate the user is anonymous
        $this->assertEquals('anonymous', (string)$response->getBody());

        // Status should still be 200 (unlike RequireAuthentication which returns 401)
        $this->assertEquals(200, $response->getStatusCode());
    }
}
