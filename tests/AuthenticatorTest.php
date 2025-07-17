<?php

namespace Dzentota\Identity\Tests;

use Dzentota\Identity\Authenticator;
use Dzentota\Identity\Exception\AuthenticationException;
use Dzentota\Identity\Tests\Mocks\MockCredentialStore;
use Dzentota\Identity\Tests\Mocks\MockSessionManager;
use Dzentota\Session\SessionManager;
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
        $identity = $this->credentialStore->fetchIdentity(
            new ServerRequest('GET', '/'), 'user123'
        );

        $request = new ServerRequest('GET', '/');
        $request = $request->withAttribute('identity', $identity);

        $retrievedIdentity = Authenticator::getIdentity($request);
        $this->assertNotNull($retrievedIdentity);
        $this->assertEquals('user123', $retrievedIdentity->getId());
    }
}
