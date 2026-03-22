<?php

declare(strict_types=1);

namespace Dzentota\Identity\Tests\Middleware;

use Dzentota\Identity\Authenticator;
use Dzentota\Identity\Middleware\InjectPasetoIdentity;
use Dzentota\Identity\Tests\Mocks\MockIdentity;
use Dzentota\Identity\Token\PasetoTokenService;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class InjectPasetoIdentityTest extends TestCase
{
    private SymmetricKey $key;
    private PasetoTokenService $tokenService;
    private InjectPasetoIdentity $middleware;

    protected function setUp(): void
    {
        $this->key          = SymmetricKey::generate();
        $this->tokenService = new PasetoTokenService($this->key);
        $this->middleware   = new InjectPasetoIdentity($this->tokenService);
    }

    public function testInjectsIdentityForValidToken(): void
    {
        $identity = new MockIdentity('user42');
        $token    = $this->tokenService->issue($identity);

        $request = (new ServerRequest('GET', '/profile'))
            ->withHeader('Authorization', 'Bearer ' . $token);

        $capturedIdentity = null;
        $handler = $this->makeHandler(function (ServerRequestInterface $req) use (&$capturedIdentity) {
            $capturedIdentity = $req->getAttribute(Authenticator::IDENTITY_ATTRIBUTE);
            return new Response(200);
        });

        $this->middleware->process($request, $handler);

        $this->assertNotNull($capturedIdentity);
        $this->assertSame('user42', $capturedIdentity->getId());
    }

    public function testPassesThroughWithoutAuthorizationHeader(): void
    {
        $request = new ServerRequest('GET', '/profile');

        $capturedIdentity = 'NOT_SET';
        $handler = $this->makeHandler(function (ServerRequestInterface $req) use (&$capturedIdentity) {
            $capturedIdentity = $req->getAttribute(Authenticator::IDENTITY_ATTRIBUTE);
            return new Response(200);
        });

        $response = $this->middleware->process($request, $handler);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertNull($capturedIdentity);
    }

    public function testPassesThroughWithInvalidToken(): void
    {
        $request = (new ServerRequest('GET', '/profile'))
            ->withHeader('Authorization', 'Bearer invalid.token.here');

        $capturedIdentity = 'NOT_SET';
        $handler = $this->makeHandler(function (ServerRequestInterface $req) use (&$capturedIdentity) {
            $capturedIdentity = $req->getAttribute(Authenticator::IDENTITY_ATTRIBUTE);
            return new Response(200);
        });

        $response = $this->middleware->process($request, $handler);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertNull($capturedIdentity);
    }

    public function testPassesThroughWithExpiredToken(): void
    {
        $expiredService = new PasetoTokenService($this->key, ['expiry' => '-1 second']);
        $token          = $expiredService->issue(new MockIdentity('user42'));

        $request = (new ServerRequest('GET', '/profile'))
            ->withHeader('Authorization', 'Bearer ' . $token);

        $capturedIdentity = 'NOT_SET';
        $handler = $this->makeHandler(function (ServerRequestInterface $req) use (&$capturedIdentity) {
            $capturedIdentity = $req->getAttribute(Authenticator::IDENTITY_ATTRIBUTE);
            return new Response(200);
        });

        $response = $this->middleware->process($request, $handler);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertNull($capturedIdentity);
    }

    private function makeHandler(callable $fn): RequestHandlerInterface
    {
        return new class ($fn) implements RequestHandlerInterface {
            private $fn;
            public function __construct(callable $fn) { $this->fn = $fn; }
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return ($this->fn)($request);
            }
        };
    }
}
