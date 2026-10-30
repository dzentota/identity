<?php

namespace Dzentota\Identity\Tests;

use Dzentota\Identity\Authenticator;
use Dzentota\Identity\Exception\AuthenticationException;
use Dzentota\Identity\Tests\Mocks\MockCredentialStore;
use Dzentota\Identity\Tests\Mocks\MockSessionManager;
use Dzentota\Session\SessionManager;
use Dzentota\Session\SessionState;
use Dzentota\Session\Value\SessionId;
use Dzentota\Session\Middleware\SessionMiddleware;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

class AuthenticatorTest extends TestCase
{
    private Authenticator $authenticator;
    private MockCredentialStore $credentialStore;
    private SessionManager $sessionManager;

    protected function setUp(): void
    {
        MockSessionManager::reset();
        $this->credentialStore = new MockCredentialStore();
        $this->sessionManager = MockSessionManager::create();
        $this->authenticator = new Authenticator(
            $this->credentialStore,
            $this->sessionManager
        );
    }

    protected function tearDown(): void
    {
        \Mockery::close();
    }

    public function testSuccessfulLogin(): void
    {
        $request = new ServerRequest('POST', '/login');

        $identity = $this->authenticator->login($request, 'testuser', 'password123');

        $this->assertEquals('user123', $identity->getId());
        $this->assertEquals('user123', $this->sessionManager->get(Authenticator::AUTH_USER_ID));
        $this->assertIsInt($this->sessionManager->get(Authenticator::AUTH_TIME));
    }

    public function testFailedLoginWithInvalidUsername(): void
    {
        $this->expectException(AuthenticationException::class);

        $request = new ServerRequest('POST', '/login');
        $this->authenticator->login($request, 'nonexistentuser', 'password123');
    }

    public function testFailedLoginWithInvalidPassword(): void
    {
        $this->expectException(AuthenticationException::class);

        $request = new ServerRequest('POST', '/login');
        $this->authenticator->login($request, 'testuser', 'wrongpassword');
    }

    public function testLogout(): void
    {
        // First login
        $request = new ServerRequest('POST', '/login');
        $this->authenticator->login($request, 'testuser', 'password123');

        // Then logout
        $this->authenticator->logout($request);

        $this->assertNull($this->sessionManager->get(Authenticator::AUTH_USER_ID));
        $this->assertNull($this->sessionManager->get(Authenticator::AUTH_TIME));
    }

    public function testIsAuthenticated(): void
    {
        $request = new ServerRequest('GET', '/');

        // Not authenticated initially
        $this->assertFalse($this->authenticator->isAuthenticated($request));

        // Authenticate
        $this->authenticator->login($request, 'testuser', 'password123');

        // Now should be authenticated
        $this->assertTrue($this->authenticator->isAuthenticated($request));
    }

    public function testGetCurrentIdentity(): void
    {
        $request = new ServerRequest('GET', '/');

        // No identity initially
        $this->assertNull($this->authenticator->getCurrentIdentity($request));

        // Authenticate
        $identity = $this->authenticator->login($request, 'testuser', 'password123');

        // Now should return the identity
        $currentIdentity = $this->authenticator->getCurrentIdentity($request);
        $this->assertNotNull($currentIdentity);
        $this->assertEquals($identity->getId(), $currentIdentity->getId());
    }

    public function testGetIdentity(): void
    {
        $identity = $this->credentialStore->fetchIdentity('user123');

        $request = new ServerRequest('GET', '/');
        $request = $request->withAttribute('identity', $identity);

        $retrievedIdentity = Authenticator::getIdentity($request);
        $this->assertNotNull($retrievedIdentity);
        $this->assertEquals('user123', $retrievedIdentity->getId());
    }

    public function testVerifyCredentialsDoesNotAuthenticate(): void
    {
        $identity = $this->authenticator->verifyCredentials('testuser', 'password123');

        $this->assertNotNull($identity);
        $this->assertEquals('user123', $identity->getId());
        $this->assertNull($this->sessionManager->get(Authenticator::AUTH_USER_ID));
        $this->assertNull($this->sessionManager->get(Authenticator::AUTH_TIME));
    }

    public function testVerifyCredentialsReturnsNullOnFailure(): void
    {
        $this->assertNull($this->authenticator->verifyCredentials('testuser', 'wrong'));
        $this->assertNull($this->authenticator->verifyCredentials('nobody', 'password123'));
    }

    public function testCompleteLoginRegeneratesAndSetsSession(): void
    {
        $session = \Mockery::mock(SessionManager::class);
        $session->shouldReceive('start')->once()->ordered()->andReturn(new SessionState(SessionId::generate()));
        $session->shouldReceive('regenerateId')->once()->ordered();
        $session->shouldReceive('set')->with(Authenticator::AUTH_USER_ID, 'user123')->once();
        $session->shouldReceive('set')->with(Authenticator::AUTH_TIME, \Mockery::type('int'))->once();
        $auth = new Authenticator($this->credentialStore, $session);

        $identity = $auth->verifyCredentials('testuser', 'password123');
        $auth->completeLogin(new ServerRequest('POST', '/login'), $identity);
        $this->addToAssertionCount(1);
    }

    public function testUsesSessionFromRequestAttribute(): void
    {
        $injected = \Mockery::mock(SessionManager::class);
        $injected->shouldNotReceive('set');
        $injected->shouldNotReceive('start');

        $data = [];
        $fromRequest = \Mockery::mock(SessionManager::class);
        $fromRequest->shouldReceive('start')->andReturn(new SessionState(SessionId::generate()));
        $fromRequest->shouldReceive('regenerateId');
        $fromRequest->shouldReceive('set')->andReturnUsing(function ($k, $v) use (&$data) { $data[$k] = $v; });
        $fromRequest->shouldReceive('get')->andReturnUsing(function ($k, $d = null) use (&$data) { return $data[$k] ?? $d; });

        $auth = new Authenticator($this->credentialStore, $injected);
        $request = (new ServerRequest('POST', '/login'))
            ->withAttribute(SessionMiddleware::SESSION_ATTRIBUTE, $fromRequest);

        $auth->login($request, 'testuser', 'password123');

        $this->assertEquals('user123', $data[Authenticator::AUTH_USER_ID]);
        $this->assertTrue($auth->isAuthenticated($request));
    }

    public function testSessionManagerIsOptionalWhenRequestCarriesOne(): void
    {
        $auth = new Authenticator($this->credentialStore);
        $request = (new ServerRequest('GET', '/'))
            ->withAttribute(SessionMiddleware::SESSION_ATTRIBUTE, $this->sessionManager);
        $this->assertFalse($auth->isAuthenticated($request));
    }

    public function testThrowsWhenNoSessionAvailable(): void
    {
        $auth = new Authenticator($this->credentialStore);
        $this->expectException(\LogicException::class);
        $auth->isAuthenticated(new ServerRequest('GET', '/'));
    }
}
