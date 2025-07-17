<?php

namespace Dzentota\Identity;

/**
 * Identity represents an authenticated entity.
 * It provides a stable identifier for session management.
 */
interface Identity
{
    /**
     * Returns a unique and stable user identifier (e.g., UUID, database ID).
     * @return string
     */
    public function getId(): string;
}
