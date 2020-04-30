<?php
declare(strict_types=1);


namespace AbsolutTicket\HttpSigAuth;

use Exception;
use HttpSignatures\Context;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard as GuardInterface;
use Illuminate\Contracts\Auth\UserProvider;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class Guard inspired by Illuminate\Auth\TokenGuard
 * @package AbsolutTicket\HttpSigAuth
 */
class Guard implements GuardInterface
{
    use GuardHelpers;

    /**
     * The request instance.
     *
     * @var ServerRequestInterface
     */
    protected $request;

    /**
     * The name of the user id "column" in persistent storage.
     *
     * @var string
     */
    protected $storageUserId;

    /**
     * Guard constructor.
     * @param ServerRequestInterface $request
     * @param UserProvider $provider
     * @param string $storageUserId
     */
    public function __construct(ServerRequestInterface $request, UserProvider $provider, $storageUserId = "id")
    {
        $this->request = $request;
        $this->setProvider($provider);
        $this->storageUserId = $storageUserId;
    }

    /**
     * @param ServerRequestInterface $request
     */
    public function setRequest(ServerRequestInterface $request)
    {
        //if the request gets set we invalidate the user
        $this->user = null;
        $this->request = $request;
    }


    /**
     * This will already try to authenticate the user by checking the signature.
     * @inheritDoc
     */
    public function user()
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (!is_null($this->user)) {
            return $this->user;
        }

        $user = null;

        $getUser = function (string $userId) use (&$user) {
            if (!empty($userId)) {
                $user = $this->provider->retrieveByCredentials([
                    $this->storageUserId => $userId,
                ]);
                if ($user == null || !$user instanceof PublicKeyEntity) {
                    return null;
                }

                return $user;
            }
            return null;
        };

        try {
            $context = new Context(['keyStore' => new KeyStore($getUser)]);

            if (!$context->verifier()->isAuthorizedWithDigest($this->request)) {
                $user = null;
            }
        } catch (Exception $e) {
            return null;
        }
        return $this->user = $user;
    }

    /**
     * @inheritDoc
     */
    public function validate(array $credentials = [])
    {
        return false; //login by credentials is not possible
    }
}