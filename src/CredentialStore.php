<?php

namespace Dzentota\Identity;

use Psr\Http\Message\ServerRequestInterface;

/**
 * CredentialStore defines the contract for user data persistence.
 */
interface CredentialStore
{
    /**
     * Fetches user credentials by login (e.g., username, email).
     * @param ServerRequestInterface $request
     * @param string $username
     * @return array|null ['id' => string, 'hash' => string] or null if user not found.
     */
    public function fetchByUsername(ServerRequestInterface $request, string $username): ?array;

    /**
     * Updates the password hash for a given user ID.
     * @param ServerRequestInterface $request
     * @param string $userId
     * @param string $newHash
     * @return void
     */
    public function updateCredentials(ServerRequestInterface $request, string $userId, string $newHash): void;

    /**
     * Fetches the full Identity object for a given user ID.
     * @param ServerRequestInterface $request
     * @param string $userId
     * @return Identity|null
     */
    public function fetchIdentity(ServerRequestInterface $request, string $userId): ?Identity;
}
