# Changelog

## Unreleased

### Added
- `Authenticator::verifyCredentials(string $username, string $password): ?Identity` is now public
  (password check with timing protection and rehash, without authenticating the session).
- `Authenticator::completeLogin(ServerRequestInterface $request, Identity $identity): void`
  to finish login for an already-verified identity (e.g. after MFA).

### Changed
- `Authenticator` resolves the session from the request attribute
  `SessionMiddleware::SESSION_ATTRIBUTE` when present, falling back to the
  constructor-injected `SessionManager`, which is now optional (`?SessionManager $sessions = null`).
- **BC break:** minimum PHP version is now 8.3 (the code already required PHP 8; the
  previous `^7.4|^8.0` constraint was incorrect).

### Fixed
- README route examples now use the real dzentota/router API (`addGroup($prefix, $callback, [$middleware])`).
