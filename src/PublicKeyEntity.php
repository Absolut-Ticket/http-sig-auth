<?php
declare(strict_types=1);


namespace AbsolutTicket\HttpSigAuth;


/**
 * Interface PublicKeyEntity
 * @package AbsolutTicket\HttpSigAuth
 */
interface PublicKeyEntity
{
    /**
     * @return string public key of this entity
     */
    public function getPublicKey(): string;

    /**
     * @return string|null hash algorithm to use for this key or null if default should be used
     */
    public function getHashAlgorithm(): ?string;
}