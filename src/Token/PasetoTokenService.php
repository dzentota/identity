<?php

declare(strict_types=1);

namespace Dzentota\Identity\Token;

use DateTimeImmutable;
use Dzentota\Identity\CredentialStore;
use Dzentota\Identity\Exception\TokenException;
use Dzentota\Identity\Identity;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Keys\Base\SymmetricKey;
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Rules\ValidAt;
use ParagonIE\Paseto\Exception\PasetoException;

/**
 * Issues and verifies PASETO v4.local (symmetric-key authenticated-encryption) tokens.
 *
 * Optionally accepts a CredentialStore: when provided, verify() fetches the full
 * Identity from the database (semi-stateful). When omitted, verify() returns a
 * lightweight TokenIdentity built from the token claims — no database hit required
 * (fully stateless).
 *
 * Usage:
 *   // Generate a key (persist the encoded form in your config):
 *   $key = SymmetricKey::generate();
 *   file_put_contents('.env', 'PASETO_KEY=' . $key->encode());
 *
 *   // Load the persisted key:
 *   $key = SymmetricKey::fromEncodedString($_ENV['PASETO_KEY']);
 *
 *   // Build the service:
 *   $tokenService = new PasetoTokenService($key, ['expiry' => '+15 minutes', 'issuer' => 'myapp']);
 *
 *   // Issue a token after successful password-based login:
 *   $token = $tokenService->issue($identity, ['role' => 'admin']);
 *
 *   // Verify on subsequent requests:
 *   $identity = $tokenService->verify($bearerToken); // null if invalid/expired
 */
class PasetoTokenService
{
    private SymmetricKey $key;
    private ?CredentialStore $store;
    private string $expiry;
    private ?string $issuer;

    /**
     * @param SymmetricKey    $key     A v4 symmetric key (32 bytes).
     *                                  Generate with SymmetricKey::generate().
     *                                  Persist and reload via encode() / fromEncodedString().
     * @param array           $options {
     *     @var string $expiry  DateTimeImmutable-compatible relative expression (default '+1 hour')
     *     @var string $issuer  Optional issuer claim (iss)
     * }
     * @param CredentialStore|null $store When provided, verify() resolves the full Identity via
     *                                     fetchIdentity(). When null, returns a TokenIdentity.
     */
    public function __construct(
        SymmetricKey $key,
        array $options = [],
        ?CredentialStore $store = null
    ) {
        $this->key    = $key;
        $this->store  = $store;
        $this->expiry = $options['expiry'] ?? '+1 hour';
        $this->issuer = $options['issuer'] ?? null;
    }

    /**
     * Issue a signed-and-encrypted PASETO v4.local token for the given Identity.
     *
     * @param Identity $identity  The authenticated identity to encode as the token subject.
     * @param array    $claims    Additional custom claims to embed in the payload.
     * @return string             The raw PASETO token string.
     * @throws TokenException     If the token cannot be built.
     */
    public function issue(Identity $identity, array $claims = []): string
    {
        try {
            $expiry  = new DateTimeImmutable($this->expiry);
            $builder = Builder::getLocal($this->key)
                ->setSubject($identity->getId())
                ->setIssuedAt()
                ->setNotBefore()
                ->setExpiration($expiry);

            if ($this->issuer !== null) {
                $builder = $builder->setIssuer($this->issuer);
            }

            foreach ($claims as $name => $value) {
                $builder = $builder->set((string) $name, $value);
            }

            return $builder->toString();
        } catch (PasetoException $e) {
            throw TokenException::issuanceFailed($e->getMessage(), $e);
        }
    }

    /**
     * Verify a token and return the corresponding Identity.
     *
     * Returns null on any failure: malformed token, bad signature, expired token,
     * or (when a store is provided) a userId that no longer exists.
     *
     * @param string $token  The raw PASETO token string.
     * @return Identity|null
     */
    public function verify(string $token): ?Identity
    {
        try {
            $parsed = Parser::getLocal($this->key)
                ->addRule(new ValidAt())
                ->parse($token);

            $userId = $parsed->getSubject();
            if ($userId === '') {
                return null;
            }

            if ($this->store !== null) {
                return $this->store->fetchIdentity($userId);
            }

            return new TokenIdentity($userId, $parsed->getClaims());
        } catch (\Throwable $e) {
            return null;
        }
    }
}
