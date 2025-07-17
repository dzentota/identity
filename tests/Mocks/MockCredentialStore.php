<?php

namespace Dzentota\Identity\Tests\Mocks;

use Dzentota\Identity\CredentialStore;
use Dzentota\Identity\Identity;
use Psr\Http\Message\ServerRequestInterface;

class MockCredentialStore implements CredentialStore
{
    private array $users = [];
    private array $credentials = [];

    public function __construct()
    {
        // Default test user
        $this->users['user123'] = new MockIdentity('user123');
        $this->credentials['testuser'] = [
            'id' => 'user123',
            'hash' => password_hash('password123', PASSWORD_ARGON2ID)
        ];
    }

    public function fetchByUsername(ServerRequestInterface $request, string $username): ?array
    {
        return $this->credentials[$username] ?? null;
    }

    public function updateCredentials(ServerRequestInterface $request, string $userId, string $newHash): void
    {
        foreach ($this->credentials as $username => $data) {
            if ($data['id'] === $userId) {
                $this->credentials[$username]['hash'] = $newHash;
                break;
            }
        }
    }

    public function fetchIdentity(ServerRequestInterface $request, string $userId): ?Identity
    {
        return $this->users[$userId] ?? null;
    }

    public function addUser(string $username, string $password, string $userId): void
    {
        $this->users[$userId] = new MockIdentity($userId);
        $this->credentials[$username] = [
            'id' => $userId,
            'hash' => password_hash($password, PASSWORD_ARGON2ID)
        ];
    }
}
