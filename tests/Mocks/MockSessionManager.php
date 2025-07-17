<?php

namespace Dzentota\Identity\Tests\Mocks;

use Dzentota\Session\SessionManager;
use Dzentota\Session\SessionState;
use Dzentota\Session\Value\SessionId;
use Psr\Http\Message\ServerRequestInterface;

/**
 * This is a helper class for creating SessionManager mocks.
 * It doesn't actually implement SessionManager itself, but provides
 * a factory method to create proper mocks.
 */
class MockSessionManager
{
    private static array $sessionData = [];

    /**
     * Creates a mock SessionManager that stores data in memory.
     *
     * @return SessionManager
     */
    public static function create(): SessionManager
    {
        $mock = \Mockery::mock(SessionManager::class);

        // Return a real SessionState object
        $mock->shouldReceive('start')
            ->andReturnUsing(function(ServerRequestInterface $request) {
                return new SessionState(SessionId::generate(), self::$sessionData);
            });

        $mock->shouldReceive('get')
            ->andReturnUsing(function($key, $default = null) {
                return self::$sessionData[$key] ?? $default;
            });

        $mock->shouldReceive('set')
            ->andReturnUsing(function($key, $value) {
                self::$sessionData[$key] = $value;
            });

        $mock->shouldReceive('remove')
            ->andReturnUsing(function($key) {
                unset(self::$sessionData[$key]);
            });

        $mock->shouldReceive('regenerateId')
            ->andReturnUsing(function() {
                // Just a mock, no actual implementation needed
            });

        $mock->shouldReceive('destroy')
            ->andReturnUsing(function() {
                self::$sessionData = [];
            });

        return $mock;
    }

    /**
     * Resets the session data (useful between tests)
     */
    public static function reset(): void
    {
        self::$sessionData = [];
    }
}
