<?php

namespace Dzentota\Identity;

use Dzentota\Session\Middleware\SessionMiddleware;
use Dzentota\Session\SessionManager;
use Psr\Http\Message\ServerRequestInterface;
use Dzentota\Identity\Exception\AuthenticationException;

/**
 * Main authentication service for managing user authentication.
 */
class Authenticator
{
    private CredentialStore $credentials;
    private ?SessionManager $sessions;
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
     * @param SessionManager|null $sessions Fallback session manager, used only when the request
     *        carries no SessionManager in the SessionMiddleware::SESSION_ATTRIBUTE attribute
     * @param array $config Argon2id hashing options (memory_cost, time_cost, threads)
     */
    public function __construct(
        CredentialStore $credentials,
        ?SessionManager $sessions = null,
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

        $this->completeLogin($request, $identity);

        return $identity;
    }

    /**
     * Mark the session as authenticated for an identity whose credentials (and any
     * additional factors) have already been verified. Regenerates the session ID
     * to prevent session fixation and records AUTH_USER_ID / AUTH_TIME.
     */
    public function completeLogin(ServerRequestInterface $request, Identity $identity): void
    {
        $session = $this->session($request);
        $session->start($request);
        $session->regenerateId();
        $session->set(self::AUTH_USER_ID, $identity->getId());
        $session->set(self::AUTH_TIME, time());
    }

    /**
     * Log the current user out, destroying the session entirely.
     */
    public function logout(ServerRequestInterface $request): void
    {
        $session = $this->session($request);
        $session->start($request);
        $session->destroy();
    }

    /**
     * Get the currently authenticated identity, or null if not authenticated.
     */
    public function getCurrentIdentity(ServerRequestInterface $request): ?Identity
    {
        $session = $this->session($request);
        $session->start($request);

        $userId = $session->get(self::AUTH_USER_ID);

        if (!$userId) {
            return null;
        }

        $identity = $this->credentials->fetchIdentity($userId);

        if (!$identity) {
            // User no longer exists; clear stale session data
            $session->remove(self::AUTH_USER_ID);
            $session->remove(self::AUTH_TIME);
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
        $session = $this->session($request);
        $session->start($request);

        if (!$session->get(self::AUTH_USER_ID)) {
            return null;
        }

        return $session->get(self::AUTH_TIME);
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
     * prevent username enumeration via response-time analysis, and transparently
     * rehashes the password if the hashing parameters changed.
     *
     * Does NOT touch the session: call completeLogin() once all factors pass.
     */
    public function verifyCredentials(string $username, string $password): ?Identity
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

    /**
     * Resolve the session manager for this request: the per-request instance put
     * there by SessionMiddleware wins over the constructor-injected fallback.
     */
    private function session(ServerRequestInterface $request): SessionManager
    {
        $fromRequest = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);
        if ($fromRequest instanceof SessionManager) {
            return $fromRequest;
        }
        if ($this->sessions !== null) {
            return $this->sessions;
        }
        throw new \LogicException(
            'No SessionManager available: add SessionMiddleware or pass one to the Authenticator constructor.'
        );
    }
}
