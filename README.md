# dzentota/identity

A secure and extensible authentication library for PHP applications.

[![Latest Version on Packagist](https://img.shields.io/packagist/v/dzentota/identity.svg)](https://packagist.org/packages/dzentota/identity)
[![PHP Version](https://img.shields.io/packagist/php-v/dzentota/identity.svg)](https://packagist.org/packages/dzentota/identity)
[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
  - [Setup](#setup)
  - [Authentication](#authentication)
  - [Protecting Routes](#protecting-routes)
- [Advanced Usage](#advanced-usage)
  - [Custom Credential Store](#custom-credential-store)
  - [Custom Identity Class](#custom-identity-class)
  - [Password Rehashing](#password-rehashing)
- [PASETO Token Authentication](#paseto-token-authentication)
  - [Setup](#paseto-setup)
  - [Issuing Tokens](#issuing-tokens)
  - [Protecting API Routes](#protecting-api-routes)
  - [Stateless vs. Semi-Stateful](#stateless-vs-semi-stateful)
  - [Hybrid Web + API](#hybrid-web--api)
- [Security Considerations](#security-considerations)
- [Integration Examples](#integration-examples)
- [Contributing](#contributing)
- [License](#license)

## Overview

The dzentota/identity library provides a secure, modern authentication solution for PHP applications. It is designed around best security practices, with special attention to OWASP recommendations, and uses Argon2id (the winner of the Password Hashing Competition) for password hashing.

Built with a clean, interface-driven architecture, the library allows for flexibility and extensibility while maintaining a simple, straightforward API.

## Overview

The dzentota/identity library provides a secure, modern authentication solution for PHP applications. It is designed around best security practices, with special attention to OWASP recommendations, and uses Argon2id (the winner of the Password Hashing Competition) for password hashing.

Built with a clean, interface-driven architecture, the library allows for flexibility and extensibility while maintaining a simple, straightforward API.

## Features

- **Secure Password Storage**: Uses Argon2id algorithm for password hashing
- **Timing-Attack Protection**: Constant-time comparison on every login attempt, even when a username is not found
- **Interface-Driven Design**: Easily extend or replace components with your own implementations
- **Clean Layer Separation**: `CredentialStore` is a pure persistence interface — no HTTP coupling
- **Stateful Sessions**: Server-side session management with integration to dzentota/session
- **PSR-15 Middleware**: Full integration with PSR-15 compatible routers and frameworks
- **PSR-17 Response Factory**: `RequireAuthentication` and `RequirePasetoToken` accept any PSR-17 `ResponseFactoryInterface`
- **Password Rehashing**: Automatic upgrades of password hashes when algorithm parameters change
- **Session Fixation Protection**: Automatic session regeneration on login
- **Full Session Destruction on Logout**: Entire session is destroyed on logout, not just auth keys
- **PASETO Token Authentication**: First-class support for API / mobile / microservice auth via [PASETO v4.local](https://github.com/paragonie/paseto) (symmetric-key authenticated encryption)

## Requirements

- PHP 7.4 or higher
- `psr/http-message` ^1.0
- `psr/http-factory` ^1.0
- `psr/http-server-middleware` ^1.0
- `dzentota/session` (dev-main)
- `paragonie/paseto` ^3.5 (pulled in automatically)

## Installation

You can install the package via composer:

```bash
composer require dzentota/identity
```

## Basic Usage

### Setup

First, create an implementation of the `CredentialStore` interface to connect to your user database:

```php
use Dzentota\Identity\CredentialStore;
use Dzentota\Identity\Identity;

class MyDatabaseStore implements CredentialStore
{
    private $db;
    
    public function __construct(PDO $db)
    {
        $this->db = $db;
    }
    
    public function fetchByUsername(string $username): ?array
    {
        $stmt = $this->db->prepare("SELECT id, password_hash FROM users WHERE username = :username");
        $stmt->execute(['username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user) {
            return null;
        }
        
        return [
            'id'   => $user['id'],
            'hash' => $user['password_hash'],
        ];
    }
    
    public function updateCredentials(string $userId, string $newHash): void
    {
        $stmt = $this->db->prepare("UPDATE users SET password_hash = :hash WHERE id = :id");
        $stmt->execute([
            'hash' => $newHash,
            'id'   => $userId,
        ]);
    }
    
    public function fetchIdentity(string $userId): ?Identity
    {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE id = :id");
        $stmt->execute(['id' => $userId]);
        $userData = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$userData) {
            return null;
        }
        
        return new User($userData);
    }
}
```

Then, implement the `Identity` interface for your User class:

```php
use Dzentota\Identity\Identity;

class User implements Identity
{
    private $id;
    private $userData;
    
    public function __construct(array $userData)
    {
        $this->userData = $userData;
        $this->id = $userData['id'];
    }
    
    public function getId(): string
    {
        return $this->id;
    }
    
    // Add your own methods to access user data
    public function getName(): string
    {
        return $this->userData['name'];
    }
    
    public function getEmail(): string
    {
        return $this->userData['email'];
    }
}
```

### Authentication

Set up the authentication service:

```php
use Dzentota\Identity\Authenticator;
use Dzentota\Session\SessionManager;
use Dzentota\Session\Storage\CacheStorage;
use Dzentota\Session\Cookie\CookieManager;

// Configure session
$cache = new YourPsrCacheImplementation();
$storage = new CacheStorage($cache);
$cookieManager = new CookieManager(
    '__Host-session',  // Cookie name with __Host- prefix for enhanced security
    true,              // Secure (HTTPS only)
    true,              // HTTP Only
    'Strict',          // Same Site policy
    '/',               // Path
    3600               // Lifetime (1 hour)
);
$sessionManager = new SessionManager($storage, $cookieManager);

// Initialize credential store
$credentialStore = new MyDatabaseStore($pdo);

// Create authenticator
$authenticator = new Authenticator(
    $credentialStore,
    $sessionManager,
    [
        'memory_cost' => PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
        'time_cost' => PASSWORD_ARGON2_DEFAULT_TIME_COST,
        'threads' => PASSWORD_ARGON2_DEFAULT_THREADS
    ]
);
```

Use the authenticator to login, check authentication status, and logout:

```php
// Login
try {
    $identity = $authenticator->login($request, $username, $password);
    // Success - $identity contains the user object
} catch (AuthenticationException $e) {
    // Authentication failed
    $errorMessage = $e->getMessage();
}

// Check if user is authenticated
if ($authenticator->isAuthenticated($request)) {
    // User is logged in
    $identity = $authenticator->getCurrentIdentity($request);
    echo "Hello, " . $identity->getName();
} else {
    // User is not logged in
    echo "Please log in";
}

// Retrieve identity injected by middleware into request attributes
$identity = Authenticator::getIdentity($request);

// Logout — destroys the entire session
$authenticator->logout($request);
```

### Protecting Routes

The library provides middleware for integrating with your router. `RequireAuthentication` requires a
PSR-17 `ResponseFactoryInterface` to build responses — use any compliant implementation:

```php
use Dzentota\Identity\Middleware\RequireAuthentication;
use Dzentota\Identity\Middleware\InjectIdentity;
use Nyholm\Psr7\Factory\Psr17Factory;

$responseFactory = new Psr17Factory(); // or any PSR-17 implementation

$router = new Router();

// Public routes
$router->get('/', HomeController::class);
$router->post('/login', LoginController::class);

// Protected routes — unauthenticated requests receive 401 JSON
$router->group('/admin', function (Router $router) {
    $router->get('/dashboard', DashboardController::class);
    $router->get('/users', UsersController::class);
})->middleware(new RequireAuthentication($authenticator, $responseFactory));

// Routes that may have authentication but don't require it
$router->get('/profile', ProfileController::class)
    ->middleware(new InjectIdentity($authenticator));
```

In your controllers, you can access the identity:

```php
public function handle(ServerRequestInterface $request): ResponseInterface
{
    $identity = Authenticator::getIdentity($request);
    
    if ($identity) {
        return $this->renderAuthenticatedView($identity);
    } else {
        return $this->renderLoginForm();
    }
}
```

## Advanced Usage

### Custom Credential Store

You can implement `CredentialStore` directly or extend `AbstractCredentialStore` as a convenience base class:

```php
use Dzentota\Identity\AbstractCredentialStore;

class RedisCredentialStore extends AbstractCredentialStore
{
    private $redis;
    
    public function __construct(Redis $redis)
    {
        $this->redis = $redis;
    }
    
    public function fetchByUsername(string $username): ?array
    {
        // ...
    }
    
    public function updateCredentials(string $userId, string $newHash): void
    {
        // ...
    }
    
    public function fetchIdentity(string $userId): ?Identity
    {
        // ...
    }
}
```

> **Note:** `CredentialStore` methods do not receive the HTTP request. If you need request-scoped
> context (e.g. tenant resolution), resolve it before constructing the store and inject it via the
> store's constructor.

### Custom Identity Class

You can implement the `Identity` interface with any class structure that suits your needs:

```php
use Dzentota\Identity\Identity;

class OAuth2User implements Identity
{
    private $providerName;
    private $providerUserId;
    
    public function __construct(string $provider, string $userId)
    {
        $this->providerName = $provider;
        $this->providerUserId = $userId;
    }
    
    public function getId(): string
    {
        // Combine provider and ID to make a globally unique ID
        return "{$this->providerName}|{$this->providerUserId}";
    }
    
    // Additional methods specific to OAuth2 users
}
```

### Password Rehashing

The library will automatically detect if a password needs rehashing (e.g., when algorithm parameters change) and update it:

```php
// To customize the hashing parameters
$authenticator = new Authenticator(
    $credentialStore,
    $sessionManager,
    [
        'memory_cost' => 65536, // 64MB
        'time_cost' => 4,       // 4 iterations
        'threads' => 1          // 1 thread
    ]
);
```

## PASETO Token Authentication

PASETO (Platform-Agnostic Security Tokens) is the recommended alternative to JWT. The library
supports **v4.local** — symmetric-key authenticated encryption — which is ideal for APIs, mobile
clients, and microservices that cannot use server-side sessions.

Both session and token auth produce the same `Identity` interface, so `Authenticator::getIdentity($request)`
works regardless of which mechanism was used.

### PASETO Setup

Generate a 32-byte symmetric key and persist its encoded form (e.g. in an environment variable).
**Never regenerate the key on each boot** — doing so invalidates all outstanding tokens.

```php
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use Dzentota\Identity\Token\PasetoTokenService;

// Run once to generate; store the result in your config/secrets:
$key = SymmetricKey::generate();
echo $key->encode(); // base64url string — put this in PASETO_KEY env var

// On every boot, load the persisted key:
$key          = SymmetricKey::fromEncodedString($_ENV['PASETO_KEY']);
$tokenService = new PasetoTokenService($key, [
    'expiry' => '+15 minutes', // any DateTimeImmutable-compatible expression
    'issuer' => 'myapp',       // optional iss claim
]);
```

### Issuing Tokens

Issue a token immediately after a successful password-based login:

```php
use Dzentota\Identity\Authenticator;
use Dzentota\Identity\Exception\AuthenticationException;

try {
    // Verify credentials and start a session (for web) or just get the Identity (for API):
    $identity = $authenticator->login($request, $username, $password);

    // Issue a PASETO token with optional custom claims:
    $token = $tokenService->issue($identity, ['role' => 'admin']);

    // Return the token to the API client:
    return new JsonResponse(['token' => $token]);
} catch (AuthenticationException $e) {
    return new JsonResponse(['error' => 'Invalid credentials'], 401);
}
```

On subsequent requests, the client sends the token in the `Authorization` header:

```
Authorization: Bearer v4.local.<...>
```

### Protecting API Routes

Use `RequirePasetoToken` to guard routes that require a valid token.
Unauthenticated requests receive a `401 Unauthorized` JSON response.

```php
use Dzentota\Identity\Middleware\RequirePasetoToken;
use Dzentota\Identity\Middleware\InjectPasetoIdentity;
use Nyholm\Psr7\Factory\Psr17Factory;

$responseFactory = new Psr17Factory(); // any PSR-17 implementation

// Hard gate — 401 if no valid token:
$router->group('/api', function (Router $router) {
    $router->get('/me', ProfileApiController::class);
    $router->get('/orders', OrdersApiController::class);
})->middleware(new RequirePasetoToken($tokenService, $responseFactory));

// Soft inject — identity available when token present, null otherwise:
$router->get('/feed', FeedController::class)
    ->middleware(new InjectPasetoIdentity($tokenService));
```

In any controller, read the resolved identity the same way as with sessions:

```php
use Dzentota\Identity\Authenticator;

public function handle(ServerRequestInterface $request): ResponseInterface
{
    $identity = Authenticator::getIdentity($request); // works for both session and token auth
    return new JsonResponse(['userId' => $identity->getId()]);
}
```

For tokens issued without a `CredentialStore`, the identity is a `TokenIdentity` and exposes
custom claims directly:

```php
use Dzentota\Identity\Token\TokenIdentity;

$identity = Authenticator::getIdentity($request);
if ($identity instanceof TokenIdentity) {
    $role   = $identity->getClaim('role');
    $tenant = $identity->getClaim('tenant', 'default');
}
```

### Stateless vs. Semi-Stateful

| Mode | How | Trade-off |
|---|---|---|
| **Stateless** | Construct `PasetoTokenService` without a `CredentialStore` | No DB hit per request; cannot revoke individual tokens |
| **Semi-stateful** | Pass a `CredentialStore` as the third argument | DB lookup on every request; instant revocation by deleting the user record |

```php
// Stateless — identity built from token claims only:
$tokenService = new PasetoTokenService($key, ['expiry' => '+15 minutes']);

// Semi-stateful — full Identity fetched from DB on each verified request:
$tokenService = new PasetoTokenService($key, ['expiry' => '+15 minutes'], $credentialStore);
```

### Hybrid Web + API

Session and token middleware can coexist on different route groups:

```php
// Web routes — session-based auth
$router->group('/app', function (Router $router) {
    $router->get('/dashboard', DashboardController::class);
})->middleware(new RequireAuthentication($authenticator, $responseFactory));

// API routes — token-based auth
$router->group('/api', function (Router $router) {
    $router->get('/data', DataApiController::class);
})->middleware(new RequirePasetoToken($tokenService, $responseFactory));
```

## Security Considerations

- **Argon2id hashing**: The current OWASP-recommended algorithm for password storage.
- **Timing-attack prevention**: When a username is not found, the library performs a constant-time dummy `password_verify()` call to eliminate timing differences that could reveal valid usernames.
- **Session fixation prevention**: Session ID is regenerated immediately on login.
- **Full session destruction on logout**: `logout()` calls `SessionManager::destroy()`, removing all session data rather than just clearing auth keys.
- **Config validation**: The constructor rejects invalid Argon2id parameters (non-positive integers) rather than silently passing them to `password_hash()`.
- **PASETO token security**: PASETO v4.local uses XChaCha20 encryption + BLAKE2b-MAC. Tokens are tamper-evident and confidential. Keep your symmetric key secret; rotate it to invalidate all outstanding tokens.
- **Token expiry**: Keep token lifetimes short (15–60 minutes). There is no built-in revocation list — use the semi-stateful mode (pass a `CredentialStore` to `PasetoTokenService`) or a separate deny-list (e.g. a Redis set of `jti` claims) if you need immediate revocation.
- **Use HTTPS**: Configure cookies with `Secure`, `HttpOnly`, and `SameSite=Strict` flags, and serve exclusively over HTTPS in production.

## Integration Examples

The `examples` folder contains complete examples of integrating the library with your application

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
