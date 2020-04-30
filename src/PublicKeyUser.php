<?php
declare(strict_types=1);


namespace AbsolutTicket\HttpSigAuth;


use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Class PublicKeyUser
 * @package AbsolutTicket\HttpSigAuth
 */
class PublicKeyUser implements Authenticatable, PublicKeyEntity
{
    /** @var string */
    private $publicKey;

    /** @var string */
    private $userId;

    /** @var string|null */
    private $hashAlgorithm;

    /**
     * PublicKeyUser constructor.
     * @param string $publicKey
     * @param string $userId
     * @param string|null $hashAlgorithm
     */
    public function __construct(string $publicKey, string $userId, ?string $hashAlgorithm = null)
    {
        $this->publicKey = $publicKey;
        $this->userId = $userId;
        $this->hashAlgorithm = $hashAlgorithm;
    }


    /**
     * @inheritDoc
     */
    public function getAuthIdentifierName()
    {
        return "fileName";
    }

    /**
     * @inheritDoc
     */
    public function getAuthIdentifier()
    {
        return $this->userId;
    }

    /**
     * @inheritDoc
     */
    public function getAuthPassword()
    {
        return ""; //no password
    }

    /**
     * @inheritDoc
     */
    public function getRememberToken()
    {
        return ""; //no remember token
    }

    /**
     * @inheritDoc
     */
    public function setRememberToken($value)
    {
        //no remember token
    }

    /**
     * @inheritDoc
     */
    public function getRememberTokenName()
    {
        return ""; //no remember token
    }

    /**
     * @inheritDoc
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * @inheritDoc
     */
    public function getHashAlgorithm(): ?string
    {
        return $this->hashAlgorithm;
    }


}