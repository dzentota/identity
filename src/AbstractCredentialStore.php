<?php

namespace Dzentota\Identity;

use Psr\Http\Message\ServerRequestInterface;

/**
 * AbstractCredentialStore provides a basic implementation of common CredentialStore functionality.
 * Extend this class to create specific credential stores for different databases or storage mechanisms.
 */
abstract class AbstractCredentialStore implements CredentialStore
{
    /**
     * Verify credentials and return identity if valid.
     *
     * @param ServerRequestInterface $request
     * @param string $username
     * @param string $password
     * @return Identity|null
     */
    public function verify(ServerRequestInterface $request, string $username, string $password): ?Identity
    {
        $credentials = $this->fetchByUsername($request, $username);

        if (!$credentials) {
            return null;
        }

        // Verify password against stored hash
        if (!password_verify($password, $credentials['hash'])) {
            return null;
        }

        // Check if password needs rehash (e.g., if hash parameters have changed)
        if (password_needs_rehash($credentials['hash'], PASSWORD_ARGON2ID)) {
            $newHash = password_hash($password, PASSWORD_ARGON2ID);
            $this->updateCredentials($request, $credentials['id'], $newHash);
        }

        return $this->fetchIdentity($request, $credentials['id']);
    }
}
