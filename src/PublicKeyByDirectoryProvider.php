<?php
declare(strict_types=1);


namespace AbsolutTicket\HttpSigAuth;


use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

/**
 * Class PublicKeyByDirectoryProvider
 * @package AbsolutTicket\HttpSigAuth
 */
class PublicKeyByDirectoryProvider implements UserProvider
{
    /** @var string */
    private $directoryPath;

    /** @var string */
    private $postFix;

    /** @var string|null */
    private $hashAlgorithm;

    /**
     * PublicKeyByDirectoryProvider constructor.
     * @param string $directoryPath
     * @param string $postFix
     * @param string|null $hashAlgorithm
     */
    public function __construct(string $directoryPath, string $postFix = ".pem", ?string $hashAlgorithm = null)
    {
        $this->directoryPath = $directoryPath;
        $this->postFix = $postFix;
        $this->hashAlgorithm = $hashAlgorithm;
    }

    /**
     * @inheritDoc
     */
    public function retrieveByToken($identifier, $token)
    {
        return null; //no token
    }

    /**
     * @inheritDoc
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        //nothing to do, no remember token
    }

    /**
     * @inheritDoc
     */
    public function retrieveByCredentials(array $credentials)
    {
        if (array_key_exists("id", $credentials)) {
            return $this->retrieveById($credentials["id"]);
        }
        return null;
    }

    /**
     * @inheritDoc
     */
    public function retrieveById($identifier)
    {
        $fileName = $identifier.$this->postFix;
        $filePath = $this->directoryPath."/".$fileName;
        $publicKey = file_get_contents($filePath);

        return new PublicKeyUser($publicKey, $identifier, $this->hashAlgorithm);
    }

    /**
     * @inheritDoc
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        return false; //credentials not verifiable
    }


}