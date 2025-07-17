<?php

namespace Dzentota\Identity;

use Dzentota\Session\SessionManager;
use Psr\Http\Message\ServerRequestInterface;
use Dzentota\Identity\Exception\AuthenticationException;

/**
 * Main authentication service for managing user authentication.
 */
class Authenticator
{
    /**
     * @var CredentialStore
     */
    private CredentialStore $credentials;

    /**
     * @var SessionManager
     */
    private SessionManager $sessions;

    /**
     * @var array
     */
    private array $config;

    /**
     * @var string The session key for storing the user ID
     */
    public const AUTH_USER_ID = 'auth_user_id';

    /**
     * @var string The session key for storing authentication time
     */
    public const AUTH_TIME = 'auth_time';

    /**
     * @var string The request attribute name for storing the identity object
     */
    public const IDENTITY_ATTRIBUTE = 'identity';

    /**
     * Create a new authenticator instance.
     *
     * @param CredentialStore $credentials
     * @param SessionManager $sessions
     * @param array $config Configuration options for password hashing
     */
    public function __construct(
        CredentialStore $credentials,
        SessionManager $sessions,
        array $config = [
            'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost' => PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads' => PASSWORD_ARGON2_DEFAULT_THREADS
        ]
    ) {
        $this->credentials = $credentials;
        $this->sessions = $sessions;
        $this->config = $config;
    }

    /**
     * Attempt to authenticate a user with the provided credentials.
     *
     * @param ServerRequestInterface $request
     * @param string $username
     * @param string $password
     * @return Identity
     * @throws AuthenticationException If authentication fails
     */
    public function login(ServerRequestInterface $request, string $username, string $password): Identity
    {
        // Get user credentials and verify password
        $identity = $this->credentials instanceof AbstractCredentialStore
            ? $this->credentials->verify($request, $username, $password)
            : $this->verifyCredentials($request, $username, $password);

        if (!$identity) {
            throw AuthenticationException::invalidCredentials();
        }

        // Start the session
        $this->sessions->start($request);

        // Regenerate session ID to prevent session fixation attacks
        $this->sessions->regenerateId();

        // Store user ID and authentication time in session
        $this->sessions->set(self::AUTH_USER_ID, $identity->getId());
        $this->sessions->set(self::AUTH_TIME, time());

        return $identity;
    }

    /**
     * Verify user credentials and return the identity if valid.
     * This method is used when the credential store doesn't extend AbstractCredentialStore.
     *
     * @param ServerRequestInterface $request
     * @param string $username
     * @param string $password
     * @return Identity|null
     */
    private function verifyCredentials(ServerRequestInterface $request, string $username, string $password): ?Identity
    {
        $credentials = $this->credentials->fetchByUsername($request, $username);

        if (!$credentials) {
            return null;
        }

        // Verify password against stored hash
        if (!password_verify($password, $credentials['hash'])) {
            return null;
        }

        // Check if password needs rehash
        if (password_needs_rehash($credentials['hash'], PASSWORD_ARGON2ID, $this->config)) {
            $newHash = password_hash($password, PASSWORD_ARGON2ID, $this->config);
            $this->credentials->updateCredentials($request, $credentials['id'], $newHash);
        }

        return $this->credentials->fetchIdentity($request, $credentials['id']);
    }

    /**
     * Log the current user out.
     *
     * @param ServerRequestInterface $request
     * @return void
     */
    public function logout(ServerRequestInterface $request): void
    {
        // Start the session
        $this->sessions->start($request);

        // Remove authentication data
        $this->sessions->remove(self::AUTH_USER_ID);
        $this->sessions->remove(self::AUTH_TIME);

        // Regenerate session ID for security
        $this->sessions->regenerateId();
    }

    /**
     * Get the currently authenticated identity.
     *
     * @param ServerRequestInterface $request
     * @return Identity|null
     */
    public function getIdentityFromSession(ServerRequestInterface $request): ?Identity
    {
        // Start the session
        $this->sessions->start($request);
        
        $userId = $this->sessions->get(self::AUTH_USER_ID);

        if (!$userId) {
            return null;
        }

        $identity = $this->credentials->fetchIdentity($request, $userId);

        if (!$identity) {
            // User no longer exists or is invalid, clear session
            $this->sessions->remove(self::AUTH_USER_ID);
            $this->sessions->remove(self::AUTH_TIME);
            return null;
        }

        return $identity;
    }

    /**
     * Check if the user is authenticated.
     *
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function check(ServerRequestInterface $request): bool
    {
        return $this->getIdentityFromSession($request) !== null;
    }

    /**
     * Alias for check() method - used in tests
     *
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function isAuthenticated(ServerRequestInterface $request): bool
    {
        return $this->check($request);
    }

    /**
     * Alias for getIdentityFromSession() - used in tests
     *
     * @param ServerRequestInterface $request
     * @return Identity|null
     */
    public function getCurrentIdentity(ServerRequestInterface $request): ?Identity
    {
        return $this->getIdentityFromSession($request);
    }

    /**
     * Get the authentication time from the session.
     *
     * @param ServerRequestInterface $request
     * @return int|null Timestamp when authentication occurred or null if not authenticated
     */
    public function getAuthTime(ServerRequestInterface $request): ?int
    {
        // Start the session
        $this->sessions->start($request);
        return $this->sessions->get(self::AUTH_TIME);
    }

    /**
     * Helper to retrieve the identity from the request attributes.
     *
     * @param ServerRequestInterface $request
     * @return Identity|null
     */
    public static function getIdentity(ServerRequestInterface $request): ?Identity
    {
        $identity = $request->getAttribute(self::IDENTITY_ATTRIBUTE);
        return $identity instanceof Identity ? $identity : null;
    }
}
