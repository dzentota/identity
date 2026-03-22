<?php

declare(strict_types=1);

namespace Dzentota\Identity\Tests\Middleware;

use Dzentota\Identity\Authenticator;
use Dzentota\Identity\Middleware\RequirePasetoToken;
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

class RequirePasetoTokenTest extends TestCase
{
    private SymmetricKey $key;
    private PasetoTokenService $tokenService;
    private RequirePasetoToken $middleware;

    protected function setUp(): void
    {
        $this->key          = SymmetricKey::generate();
        $this->tokenService = new PasetoTokenService($this->key);
        $this->middleware   = new RequirePasetoToken($this->tokenService, new Psr17Factory());
    }

    public function testAllowsRequestWithValidToken(): void
    {
        $identity = new MockIdentity('user42');
        $token    = $this->tokenService->issue($identity);

        $request = (new ServerRequest('GET', '/api/data'))
            ->withHeader('Authorization', 'Bearer ' . $token);

        $handler  = $this->makePassthroughHandler();
        $response = $this->middleware->process($request, $handler);

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testInjectsIdentityIntoRequestAttributes(): void
    {
        $identity = new MockIdentity('user42');
        $token    = $this->tokenService->issue($identity);

        $request = (new ServerRequest('GET', '/api/data'))
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

    public function testReturns401WithNoAuthorizationHeader(): void
    {
        $request  = new ServerRequest('GET', '/api/data');
        $response = $this->middleware->process($request, $this->makePassthroughHandler());

        $this->assertSame(401, $response->getStatusCode());
    }

    public function testReturns401WithInvalidToken(): void
    {
        $request = (new ServerRequest('GET', '/api/data'))
            ->withHeader('Authorization', 'Bearer not.a.valid.token');

        $response = $this->middleware->process($request, $this->makePassthroughHandler());

        $this->assertSame(401, $response->getStatusCode());
    }

    public function testReturns401WithExpiredToken(): void
    {
        $expiredService = new PasetoTokenService($this->key, ['expiry' => '-1 second']);
        $token          = $expiredService->issue(new MockIdentity('user42'));

        $request = (new ServerRequest('GET', '/api/data'))
            ->withHeader('Authorization', 'Bearer ' . $token);

        $response = $this->middleware->process($request, $this->makePassthroughHandler());

        $this->assertSame(401, $response->getStatusCode());
    }

    public function testReturns401WithWrongKey(): void
    {
        $otherService = new PasetoTokenService(SymmetricKey::generate());
        $token        = $otherService->issue(new MockIdentity('user42'));

        $request = (new ServerRequest('GET', '/api/data'))
            ->withHeader('Authorization', 'Bearer ' . $token);

        $response = $this->middleware->process($request, $this->makePassthroughHandler());

        $this->assertSame(401, $response->getStatusCode());
    }

    public function test401ResponseContainsJsonContentType(): void
    {
        $request  = new ServerRequest('GET', '/api/data');
        $response = $this->middleware->process($request, $this->makePassthroughHandler());

        $this->assertSame('application/json', $response->getHeaderLine('Content-Type'));
    }

    public function testHandlerIsNotCalledOnUnauthorizedRequest(): void
    {
        $handlerCalled = false;
        $handler = $this->makeHandler(function () use (&$handlerCalled) {
            $handlerCalled = true;
            return new Response(200);
        });

        $this->middleware->process(new ServerRequest('GET', '/api/data'), $handler);

        $this->assertFalse($handlerCalled);
    }

    private function makePassthroughHandler(): RequestHandlerInterface
    {
        return $this->makeHandler(fn() => new Response(200));
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
