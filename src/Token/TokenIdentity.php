<?php

declare(strict_types=1);

namespace Dzentota\Identity\Token;

use Dzentota\Identity\Identity;

/**
 * A lightweight Identity built from PASETO token claims.
 * Used when no CredentialStore is provided to PasetoTokenService — avoids a
 * database round-trip on every token-authenticated request.
 */
class TokenIdentity implements Identity
{
    private string $id;
    private array $claims;

    public function __construct(string $id, array $claims = [])
    {
        $this->id = $id;
        $this->claims = $claims;
    }

    public function getId(): string
    {
        return $this->id;
    }

    /**
     * Return a single claim value by name, or $default if absent.
     */
    public function getClaim(string $name, mixed $default = null): mixed
    {
        return $this->claims[$name] ?? $default;
    }

    /**
     * Return all claims embedded in the token.
     */
    public function getClaims(): array
    {
        return $this->claims;
    }
}
