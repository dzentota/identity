<?php

namespace Dzentota\Identity\Tests\Exception;

use Dzentota\Identity\Exception\AuthenticationException;
use PHPUnit\Framework\TestCase;

class AuthenticationExceptionTest extends TestCase
{
    public function testExceptionInheritance(): void
    {
        $exception = new AuthenticationException('Authentication failed');
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals('Authentication failed', $exception->getMessage());
    }
}
