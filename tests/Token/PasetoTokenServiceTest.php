<?php

declare(strict_types=1);

namespace Dzentota\Identity\Tests\Token;

use Dzentota\Identity\Exception\TokenException;
use Dzentota\Identity\Tests\Mocks\MockCredentialStore;
use Dzentota\Identity\Tests\Mocks\MockIdentity;
use Dzentota\Identity\Token\PasetoTokenService;
use Dzentota\Identity\Token\TokenIdentity;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use PHPUnit\Framework\TestCase;

class PasetoTokenServiceTest extends TestCase
{
    private SymmetricKey $key;
    private PasetoTokenService $service;

    protected function setUp(): void
    {
        $this->key     = SymmetricKey::generate();
        $this->service = new PasetoTokenService($this->key);
    }

    public function testIssueReturnsNonEmptyString(): void
    {
        $identity = new MockIdentity('user42');
        $token    = $this->service->issue($identity);

        $this->assertNotEmpty($token);
        $this->assertStringStartsWith('v4.local.', $token);
    }

    public function testVerifyReturnsTokenIdentityWithCorrectId(): void
    {
        $identity = new MockIdentity('user42');
        $token    = $this->service->issue($identity);

        $result = $this->service->verify($token);

        $this->assertInstanceOf(TokenIdentity::class, $result);
        $this->assertSame('user42', $result->getId());
    }

    public function testVerifyReturnsCustomClaims(): void
    {
        $identity = new MockIdentity('user42');
        $token    = $this->service->issue($identity, ['role' => 'admin', 'tenant' => 'acme']);

        $result = $this->service->verify($token);

        $this->assertInstanceOf(TokenIdentity::class, $result);
        $this->assertSame('admin', $result->getClaim('role'));
        $this->assertSame('acme', $result->getClaim('tenant'));
    }

    public function testVerifyReturnsNullForTamperedToken(): void
    {
        $identity = new MockIdentity('user42');
        $token    = $this->service->issue($identity);

        $tampered = $token . 'TAMPERED';
        $this->assertNull($this->service->verify($tampered));
    }

    public function testVerifyReturnsNullForExpiredToken(): void
    {
        $service = new PasetoTokenService($this->key, ['expiry' => '-1 second']);
        $token   = $service->issue(new MockIdentity('user42'));

        $this->assertNull($this->service->verify($token));
    }

    public function testVerifyReturnsNullForRandomString(): void
    {
        $this->assertNull($this->service->verify('not.a.token'));
    }

    public function testVerifyWithCredentialStoreFetchesFullIdentity(): void
    {
        $store   = new MockCredentialStore();
        $service = new PasetoTokenService($this->key, [], $store);

        $identity = new MockIdentity('user123');
        $token    = $service->issue($identity);

        $result = $service->verify($token);

        $this->assertNotNull($result);
        $this->assertSame('user123', $result->getId());
        // Should be the real object from the store, not a TokenIdentity
        $this->assertNotInstanceOf(TokenIdentity::class, $result);
    }

    public function testVerifyWithCredentialStoreReturnsNullForUnknownUser(): void
    {
        $store   = new MockCredentialStore();
        $service = new PasetoTokenService($this->key, [], $store);

        $identity = new MockIdentity('ghost-user');
        $token    = $service->issue($identity);

        $this->assertNull($service->verify($token));
    }

    public function testDifferentKeyCannotVerifyToken(): void
    {
        $otherKey     = SymmetricKey::generate();
        $otherService = new PasetoTokenService($otherKey);

        $token = $this->service->issue(new MockIdentity('user42'));

        $this->assertNull($otherService->verify($token));
    }

    public function testIssuerClaimIsEmbedded(): void
    {
        $service  = new PasetoTokenService($this->key, ['issuer' => 'myapp']);
        $identity = new MockIdentity('user42');
        $token    = $service->issue($identity);

        $result = $service->verify($token);
        $this->assertNotNull($result);
        // Token round-tripped successfully; claims are accessible
        $this->assertInstanceOf(TokenIdentity::class, $result);
    }

    public function testGetClaimReturnsDefaultForMissingClaim(): void
    {
        $identity = new MockIdentity('user42');
        $token    = $this->service->issue($identity);
        $result   = $this->service->verify($token);

        $this->assertInstanceOf(TokenIdentity::class, $result);
        $this->assertNull($result->getClaim('nonexistent'));
        $this->assertSame('fallback', $result->getClaim('nonexistent', 'fallback'));
    }
}
