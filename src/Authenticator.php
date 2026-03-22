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
    private CredentialStore $credentials;
    private SessionManager $sessions;
    private array $config;

    /** @var string The session key for storing the user ID */
    public const AUTH_USER_ID = 'auth_user_id';

    /** @var string The session key for storing authentication time */
    public const AUTH_TIME = 'auth_time';

    /** @var string The request attribute name for storing the identity object */
    public const IDENTITY_ATTRIBUTE = 'identity';

    /**
     * A pre-computed Argon2id hash used for constant-time dummy comparisons,
     * preventing username enumeration via timing attacks.
     */
    private const DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=1$ODhZc1hJTU5jcWNrT3A2dg$myF/TEMLcEgdxJ5HfTNQbr9I5QNqEPrzbwBWm3Hpzbc';

    /**
     * @param CredentialStore $credentials
     * @param SessionManager $sessions
     * @param array $config Argon2id hashing options (memory_cost, time_cost, threads)
     */
    public function __construct(
        CredentialStore $credentials,
        SessionManager $sessions,
        array $config = [
            'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
            'time_cost'   => PASSWORD_ARGON2_DEFAULT_TIME_COST,
            'threads'     => PASSWORD_ARGON2_DEFAULT_THREADS,
        ]
    ) {
        foreach (['memory_cost', 'time_cost', 'threads'] as $key) {
            if (!isset($config[$key]) || !is_int($config[$key]) || $config[$key] < 1) {
                throw new \InvalidArgumentException("Config '{$key}' must be a positive integer.");
            }
        }

        $this->credentials = $credentials;
        $this->sessions = $sessions;
        $this->config = $config;
    }

    /**
     * Attempt to authenticate a user with the provided credentials.
     *
     * @throws AuthenticationException If authentication fails
     */
    public function login(ServerRequestInterface $request, string $username, string $password): Identity
    {
        $identity = $this->verifyCredentials($username, $password);

        if (!$identity) {
            throw AuthenticationException::invalidCredentials();
        }

        $this->sessions->start($request);
        $this->sessions->regenerateId();
        $this->sessions->set(self::AUTH_USER_ID, $identity->getId());
        $this->sessions->set(self::AUTH_TIME, time());

        return $identity;
    }

    /**
     * Log the current user out, destroying the session entirely.
     */
    public function logout(ServerRequestInterface $request): void
    {
        $this->sessions->start($request);
        $this->sessions->destroy();
    }

    /**
     * Get the currently authenticated identity, or null if not authenticated.
     */
    public function getCurrentIdentity(ServerRequestInterface $request): ?Identity
    {
        $this->sessions->start($request);

        $userId = $this->sessions->get(self::AUTH_USER_ID);

        if (!$userId) {
            return null;
        }

        $identity = $this->credentials->fetchIdentity($userId);

        if (!$identity) {
            // User no longer exists; clear stale session data
            $this->sessions->remove(self::AUTH_USER_ID);
            $this->sessions->remove(self::AUTH_TIME);
            return null;
        }

        return $identity;
    }

    /**
     * Check whether the current request belongs to an authenticated user.
     */
    public function isAuthenticated(ServerRequestInterface $request): bool
    {
        return $this->getCurrentIdentity($request) !== null;
    }

    /**
     * Return the timestamp when authentication occurred, or null if not authenticated.
     */
    public function getAuthTime(ServerRequestInterface $request): ?int
    {
        $this->sessions->start($request);

        if (!$this->sessions->get(self::AUTH_USER_ID)) {
            return null;
        }

        return $this->sessions->get(self::AUTH_TIME);
    }

    /**
     * Retrieve the identity injected into request attributes by middleware.
     */
    public static function getIdentity(ServerRequestInterface $request): ?Identity
    {
        $identity = $request->getAttribute(self::IDENTITY_ATTRIBUTE);
        return $identity instanceof Identity ? $identity : null;
    }

    /**
     * Verify credentials and return the matching Identity, or null on failure.
     * Uses a constant-time dummy comparison when the username is not found to
     * prevent username enumeration via response-time analysis.
     */
    private function verifyCredentials(string $username, string $password): ?Identity
    {
        $credentials = $this->credentials->fetchByUsername($username);

        if (!$credentials) {
            password_verify($password, self::DUMMY_HASH);
            return null;
        }

        if (!password_verify($password, $credentials['hash'])) {
            return null;
        }

        if (password_needs_rehash($credentials['hash'], PASSWORD_ARGON2ID, $this->config)) {
            $newHash = password_hash($password, PASSWORD_ARGON2ID, $this->config);
            $this->credentials->updateCredentials($credentials['id'], $newHash);
        }

        return $this->credentials->fetchIdentity($credentials['id']);
    }
}
