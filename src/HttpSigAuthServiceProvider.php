<?php
declare(strict_types=1);


namespace AbsolutTicket\HttpSigAuth;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\ServiceProvider as BaseServiceProvider;
use Psr\Http\Message\ServerRequestInterface;


/**
 * Class HttpSigAuthServiceProvider
 * @package AbsolutTicket\HttpSigAuth
 */
class HttpSigAuthServiceProvider extends BaseServiceProvider
{
    /**
     * Boot the service provider
     *
     */
    public function boot()
    {

        Auth::extend('http-sig',
            function ($app, /** @noinspection PhpUnusedParameterInspection */ $name, array $config) {
                $guard = new Guard($app->make(ServerRequestInterface::class),
                    Auth::createUserProvider($config['provider']), Config::get('httpsig.storageUserId', 'id'));

                $app->refresh('request', $guard, 'setRequest');

                return $guard;
            });

        Auth::provider('public-key-by-directory', function () {
            // Return an instance of Illuminate\Contracts\Auth\UserProvider...
            return new PublicKeyByDirectoryProvider(
                Config::get('httpsig.publicKeyDirectory', Storage::disk()->path('public_keys')),
                Config::get('httpsig.publicKeyPostFix', '.pem'),
                Config::get('httpsig.verifyingHashAlgorithm', 'sha512')
            );
        });


    }

}