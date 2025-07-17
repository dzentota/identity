<?php

namespace Dzentota\Identity\Tests\Mocks;

use Dzentota\Identity\Identity;

class MockIdentity implements Identity
{
    private string $id;

    public function __construct(string $id = '123456')
    {
        $this->id = $id;
    }

    public function getId(): string
    {
        return $this->id;
    }
}
