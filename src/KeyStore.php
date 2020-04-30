<?php
declare(strict_types=1);


namespace AbsolutTicket\HttpSigAuth;


use HttpSignatures\Key;
use HttpSignatures\KeyException;
use HttpSignatures\KeyStoreException;
use HttpSignatures\KeyStoreInterface;

/**
 * Class KeyStore
 * @package AbsolutTicket\HttpSigAuth
 */
class KeyStore implements KeyStoreInterface
{
    private $getPublicKeyCallback;

    /**
     * KeyStore constructor.
     * @param $getPublicKeyCallback
     */
    public function __construct($getPublicKeyCallback)
    {
        $this->getPublicKeyCallback = $getPublicKeyCallback;
    }


    /**
     * @inheritDoc
     */
    public function fetch(?string $keyId = null): Key
    {
        /** @var PublicKeyEntity $user */
        $user = ($this->getPublicKeyCallback)($keyId);
        if ($user == null) {
            throw new KeyStoreException();
        }
        try {
            return new Key($keyId, $user->getPublicKey(), $user->getHashAlgorithm());
        } catch (KeyException $exception) {
            throw new KeyStoreException($exception->getMessage());
        }
    }
}