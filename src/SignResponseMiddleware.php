<?php
declare(strict_types=1);


namespace AbsolutTicket\HttpSigAuth;


use Closure;
use Exception;
use HttpSignatures\Context;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Storage;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class SignResponseMiddleware
 * @package AbsolutTicket\HttpSigAuth
 */
class SignResponseMiddleware
{

    /**
     * @param $request
     * @param Closure $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $response = $next($request);

        $psrResponse = self::getPsrResponse($response);

        $psrResponse = self::signResponse($psrResponse, $request);

        return self::getResponse($psrResponse);
    }

    private static function getPsrResponse(Response $response): ResponseInterface
    {
        $psr17Factory = new Psr17Factory();
        $psrHttpFactory = new PsrHttpFactory($psr17Factory, $psr17Factory, $psr17Factory, $psr17Factory);
        return $psrHttpFactory->createResponse($response);
    }

    private static function signResponse(ResponseInterface $response, Request $request): ResponseInterface
    {
        $headers = Config::get('httpsig.signingHeaders',
            ['(created)', '(expires)', 'Digest', 'Request-Authorization-Digest']);

        if (in_array('Request-Authorization-Digest', $headers)) {
            //add Request-Authorization-Digest
            $response = self::withRequestAuthorizationDigest($response, $request);
        }

        try {
            $context = new Context([
                'keys' => [Config::get('httpsig.serverPrivateKeyId', 'server') =>
                    Config::get('httpsig.serverPrivateKeyFile', Storage::disk()->path('private_keys/server.pem'))],
                'hashAlgorithm' => Config::get('httpsig.signingHashAlgorithm', 'sha512'),
                'algorithm' => 'hs2019',
                'headers' => $headers,
                'digestHashAlgorithm' => Config::get('httpsig.digestingHashAlgorithm', 'sha512')
            ]);
            $context->setExpires("+300");
            if (in_array('Digest', $headers)) {
                $response = $context->signer()->signWithDigest($response);
            } else {
                $response = $context->signer()->sign($response);
            }
        } catch (Exception $e) {
            //TODO what to do here?
        }
        return $response;
    }

    /**
     * @param ResponseInterface $response
     * @param Request $request
     * @return ResponseInterface
     */
    private static function withRequestAuthorizationDigest(ResponseInterface $response, $request): ResponseInterface
    {
        $requestAuthorizationHeader = $request->headers->get('Authorization', '');
        $digestAlgorithm = Config::get('httpsig.requestAuthorizationDigestAlgorithm', 'sha512');

        $hashName = 'sha1';
        $digestHeaderPrefix = "SHA";

        switch ($digestAlgorithm) {
            case 'sha':
            case 'sha1':
                $hashName = 'sha1';
                $digestHeaderPrefix = 'SHA';
                break;
            case 'sha256':
                $hashName = 'sha256';
                $digestHeaderPrefix = 'SHA-256';
                break;
            case 'sha512':
                $hashName = 'sha512';
                $digestHeaderPrefix = 'SHA-512';
                break;
        }

        $header = $digestHeaderPrefix.'='.base64_encode(hash($hashName, $requestAuthorizationHeader, true));

        return $response->withHeader('Request-Authorization-Digest', $header);
    }

    private function getResponse(ResponseInterface $response): Response
    {
        $httpFoundationFactory = new HttpFoundationFactory();
        return $httpFoundationFactory->createResponse($response);
    }
}