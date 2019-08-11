<?php
declare(strict_types=1);
/**
 * Created by PhpStorm.
 * User: Dyorg Washington G. Almeida
 * Date: 27/08/2018
 * Time: 21:54
 */

namespace Dyorg\TokenAuthentication;

use PHPUnit\Framework\TestCase;
use Slim\Factory\ServerRequestCreatorFactory;

class TokenSearchTest extends TestCase
{
    private static $token = 'VGhpcyBpcyBzb21lIHRleHQgdG8gY29udmVydCB2aWEgQ3J5cHQu';

    public function test_should_found_token_from_header()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token);

        $tokenSearch = new TokenSearch([
            'header' => 'Authorization',
            'regex' => '/^Bearer\s(.*)$/'
        ]);

        $token = $tokenSearch->getToken($request);

        $this->assertEquals(self::$token, $token);
    }

    public function test_should_found_token_from_cookie()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withCookieParams([
                'authorization' => self::$token
            ]);

        $tokenSearch = new TokenSearch([
            'cookie' => 'authorization'
        ]);

        $token = $tokenSearch->getToken($request);

        $this->assertEquals(self::$token, $token);
    }

    public function test_should_found_token_from_parameter()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withQueryParams([
                'authorization' => self::$token
            ]);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $tokenSearch = new TokenSearch([
            'parameter' => 'authorization'
        ]);

        $token = $tokenSearch->getToken($request);

        $this->assertEquals(self::$token, $token);
    }

    /**
     * @expectedException Dyorg\TokenAuthentication\Exceptions\TokenNotFoundException
     */
    public function test_exception_when_token_not_found()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals();

        (new TokenSearch([]))->getToken($request);
    }

    public function test_should_return_token_in_attribute()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token);

        $tokenSearch = new TokenSearch([
            'header' => 'Authorization',
            'regex' => '/^Bearer\s(.*)$/',
            'attribute' => 'token'
        ]);

        $tokenSearch->getToken($request);

        $this->assertEquals(self::$token, $request->getAttribute('token'));
    }
}
