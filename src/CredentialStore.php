<?php

namespace Dzentota\Identity;

/**
 * CredentialStore defines the contract for user data persistence.
 */
interface CredentialStore
{
    /**
     * Fetches user credentials by login (e.g., username, email).
     * @param string $username
     * @return array|null ['id' => string, 'hash' => string] or null if user not found.
     */
    public function fetchByUsername(string $username): ?array;

    /**
     * Updates the password hash for a given user ID.
     * @param string $userId
     * @param string $newHash
     * @return void
     */
    public function updateCredentials(string $userId, string $newHash): void;

    /**
     * Fetches the full Identity object for a given user ID.
     * @param string $userId
     * @return Identity|null
     */
    public function fetchIdentity(string $userId): ?Identity;
}
