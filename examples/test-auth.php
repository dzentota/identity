<?php

/**
 * This is a simple script to test authentication functionality in one PHP execution
 * It simulates multiple requests but within one process, avoiding cookie-related issues
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Dzentota\Identity\Authenticator;
use Dzentota\Identity\Exception\AuthenticationException;
use Dzentota\Session\Cookie\CookieManager;
use Dzentota\Session\SessionManager;
use Dzentota\Session\Storage\CacheStorage;
use Nyholm\Psr7\ServerRequest;
use Psr\Http\Message\ServerRequestInterface;

// Example credential store implementation (same as in basic-usage.php)
class ExampleCredentialStore implements \Dzentota\Identity\CredentialStore
{
    private $users = [];

    public function __construct()
    {
        // Add a test user
        $this->users['admin'] = [
            'id' => 'user123',
            'hash' => password_hash('password', PASSWORD_ARGON2ID),
            'name' => 'Administrator'
        ];
    }

    public function fetchByUsername(ServerRequestInterface $request, string $username): ?array
    {
        if (!isset($this->users[$username])) {
            return null;
        }

        return [
            'id' => $this->users[$username]['id'],
            'hash' => $this->users[$username]['hash']
        ];
    }

    public function updateCredentials(ServerRequestInterface $request, string $userId, string $newHash): void
    {
        foreach ($this->users as $username => $userData) {
            if ($userData['id'] === $userId) {
                $this->users[$username]['hash'] = $newHash;
                break;
            }
        }
    }

    public function fetchIdentity(ServerRequestInterface $request, string $userId): ?\Dzentota\Identity\Identity
    {
        foreach ($this->users as $userData) {
            if ($userData['id'] === $userId) {
                return new ExampleUser($userData['id'], $userData['name']);
            }
        }

        return null;
    }
}

// Example user implementation
class ExampleUser implements \Dzentota\Identity\Identity
{
    private $id;
    private $name;

    public function __construct(string $id, string $name)
    {
        $this->id = $id;
        $this->name = $name;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }
}

// Use persistent cache to maintain session state
$cache = new class implements \Psr\SimpleCache\CacheInterface {
    private $data = [];

    public function get($key, $default = null)
    {
        return $this->data[$key] ?? $default;
    }

    public function set($key, $value, $ttl = null)
    {
        $this->data[$key] = $value;
        return true;
    }

    public function delete($key)
    {
        unset($this->data[$key]);
        return true;
    }

    public function clear()
    {
        $this->data = [];
        return true;
    }

    public function getMultiple($keys, $default = null)
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }
        return $result;
    }

    public function setMultiple($values, $ttl = null)
    {
        foreach ($values as $key => $value) {
            $this->data[$key] = $value;
        }
        return true;
    }

    public function deleteMultiple($keys)
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }
        return true;
    }

    public function has($key)
    {
        return isset($this->data[$key]);
    }
};

$storage = new CacheStorage($cache);
$cookieManager = new CookieManager(
    'session',
    false,
    true,
    'Lax',
    '/',
    3600
);

// Initialize session manager and authenticator
$sessionManager = new SessionManager($storage, $cookieManager);
$credentialStore = new ExampleCredentialStore();
$authenticator = new Authenticator(
    $credentialStore,
    $sessionManager
);

// Create test requests
$loginRequest = new ServerRequest('POST', '/login');
$profileRequest = new ServerRequest('GET', '/profile');

echo "=== Authentication Test ===\n\n";

// Step 1: Try accessing profile before login (should fail)
echo "Step 1: Accessing profile before login\n";
if (!$authenticator->check($profileRequest)) {
    echo "✓ Authentication check correctly returns false\n";
} else {
    echo "✗ Authentication check incorrectly returns true\n";
}

$identity = $authenticator->getIdentityFromSession($profileRequest);
if ($identity === null) {
    echo "✓ getIdentityFromSession() correctly returns null\n";
} else {
    echo "✗ getIdentityFromSession() incorrectly returns an identity\n";
}

// Step 2: Perform login
echo "\nStep 2: Performing login\n";
try {
    $identity = $authenticator->login($loginRequest, 'admin', 'password');
    echo "✓ Login successful\n";
    echo "✓ User ID: " . $identity->getId() . "\n";
    echo "✓ User name: " . ($identity instanceof ExampleUser ? $identity->getName() : 'Unknown') . "\n";
} catch (AuthenticationException $e) {
    echo "✗ Login failed: " . $e->getMessage() . "\n";
    exit(1);
}

// Step 3: Check authentication after login
echo "\nStep 3: Checking authentication after login\n";
if ($authenticator->check($profileRequest)) {
    echo "✓ Authentication check correctly returns true\n";
} else {
    echo "✗ Authentication check incorrectly returns false\n";
}

$identity = $authenticator->getIdentityFromSession($profileRequest);
if ($identity !== null) {
    echo "✓ getIdentityFromSession() correctly returns an identity\n";
    echo "✓ Authenticated user ID: " . $identity->getId() . "\n";
} else {
    echo "✗ getIdentityFromSession() incorrectly returns null\n";
}

// Step 4: Logout
echo "\nStep 4: Performing logout\n";
$authenticator->logout($profileRequest);
echo "✓ Logout executed\n";

// Step 5: Check authentication after logout
echo "\nStep 5: Checking authentication after logout\n";
if (!$authenticator->check($profileRequest)) {
    echo "✓ Authentication check correctly returns false after logout\n";
} else {
    echo "✗ Authentication check incorrectly returns true after logout\n";
}

// Step 6: Try to login with incorrect password
echo "\nStep 6: Trying login with incorrect password\n";
try {
    $authenticator->login($loginRequest, 'admin', 'wrong_password');
    echo "✗ Login incorrectly succeeded with wrong password\n";
} catch (AuthenticationException $e) {
    echo "✓ Login correctly failed with wrong password: " . $e->getMessage() . "\n";
}

// Step 7: Try to login with incorrect username
echo "\nStep 7: Trying login with incorrect username\n";
try {
    $authenticator->login($loginRequest, 'nonexistent', 'password');
    echo "✗ Login incorrectly succeeded with wrong username\n";
} catch (AuthenticationException $e) {
    echo "✓ Login correctly failed with wrong username: " . $e->getMessage() . "\n";
}

echo "\n=== Test Complete ===\n";
