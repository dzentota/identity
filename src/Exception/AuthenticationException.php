<?php

namespace Dzentota\Identity\Exception;

/**
 * Exception thrown when authentication fails.
 */
class AuthenticationException extends \Exception
{
    /**
     * Create a new authentication exception for invalid credentials.
     *
     * @return self
     */
    public static function invalidCredentials(): self
    {
        return new self('Invalid username or password');
    }

    /**
     * Create a new authentication exception for when authentication is required.
     *
     * @return self
     */
    public static function authenticationRequired(): self
    {
        return new self('Authentication required');
    }
}
