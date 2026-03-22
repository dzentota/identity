<?php

declare(strict_types=1);

namespace Dzentota\Identity\Exception;

/**
 * Exception thrown for PASETO token errors.
 */
class TokenException extends \Exception
{
    public static function expired(): self
    {
        return new self('The token has expired.');
    }

    public static function invalid(string $reason = ''): self
    {
        $message = 'The token is invalid.';
        if ($reason !== '') {
            $message .= ' ' . $reason;
        }
        return new self($message);
    }

    public static function issuanceFailed(string $reason = '', ?\Throwable $previous = null): self
    {
        $message = 'Token issuance failed.';
        if ($reason !== '') {
            $message .= ' ' . $reason;
        }
        return new self($message, 0, $previous);
    }
}
