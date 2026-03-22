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
- **PSR-17 Response Factory**: `RequireAuthentication` accepts any PSR-17 `ResponseFactoryInterface`
- **Password Rehashing**: Automatic upgrades of password hashes when algorithm parameters change
- **Session Fixation Protection**: Automatic session regeneration on login
- **Full Session Destruction on Logout**: Entire session is destroyed on logout, not just auth keys

## Requirements

- PHP 7.4 or higher
- `psr/http-message` ^1.0
- `psr/http-factory` ^1.0
- `psr/http-server-middleware` ^1.0
- `dzentota/session` (dev-main)

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

## Security Considerations

- **Argon2id hashing**: The current OWASP-recommended algorithm for password storage.
- **Timing-attack prevention**: When a username is not found, the library performs a constant-time dummy `password_verify()` call to eliminate timing differences that could reveal valid usernames.
- **Session fixation prevention**: Session ID is regenerated immediately on login.
- **Full session destruction on logout**: `logout()` calls `SessionManager::destroy()`, removing all session data rather than just clearing auth keys.
- **Config validation**: The constructor rejects invalid Argon2id parameters (non-positive integers) rather than silently passing them to `password_hash()`.
- **Use HTTPS**: Configure cookies with `Secure`, `HttpOnly`, and `SameSite=Strict` flags, and serve exclusively over HTTPS in production.

## Integration Examples

The `examples` folder contains complete examples of integrating the library with your application

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
