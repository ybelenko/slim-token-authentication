<?php
declare(strict_types=1);
/**
 * Created by PhpStorm.
 * User: Dyorg Washington G. Almeida
 * Date: 27/08/2018
 * Time: 21:54
 */

namespace Dyorg;

use Dyorg\TokenAuthentication\Exceptions\UnauthorizedException;
use Dyorg\TokenAuthentication\Exceptions\UnauthorizedExceptionInterface;
use Dyorg\TokenAuthentication\TokenSearch;
use Dyorg\Handlers\ResponseInitHandler;
use Dyorg\Handlers\ResponseTokenHandler;
use Dyorg\Handlers\ResponseUsernameHandler;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\CallableResolver;
use Slim\Routing\RouteCollector;
use Slim\Routing\RouteResolver;
use Slim\Factory\AppFactory;
use Slim\Factory\ServerRequestCreatorFactory;

class TokenAuthenticationTest extends TestCase
{
    private static $token = 'VGhpcyBpcyBzb21lIHRleHQgdG8gY29udmVydCB2aWEgQ3J5cHQu';

    private static $token_invalid = 's8E6nodLhR56nqIgjMGR88bHeJEXJxsP';

    private static $user = [ 'name' => 'Acme' ];

    private static $wrong_token_message = 'Wrong token Message';

    public function validAuthenticator(ServerRequestInterface &$request, TokenSearch $tokenSearch) : bool
    {
        $token = $tokenSearch->getToken($request);

        if ($token !== self::$token)
            throw new UnauthorizedException(self::$wrong_token_message);

        $request = $request->withAttribute('user_from_inside_authenticator', self::$user);

        return true;
    }

    public function authenticatorWithReturnFalseWhenUnauthorized(ServerRequestInterface &$request, TokenSearch $tokenSearch) : bool
    {
        $token = $tokenSearch->getToken($request);

        if ($token !== self::$token)
            return false;

        return true;
    }

    public function test_token_authentication_is_instantiable()
    {
        $token_authentication = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator']
        ]);

        $this->assertInstanceOf(TokenAuthentication::class, $token_authentication);
    }

    /**
     * @dataProvider invalidCallables
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessageRegExp /authenticator.+not.+setted/i
     */
    public function test_exception_when_authenticator_is_not_especified()
    {
        new TokenAuthentication([]);
    }

    public function invalidCallables()
    {
        return [
            [''],
            [0],
            [1],
            [true],
            [false],
            ['callable'],
            ['string'],
            [[]],
            [['acme', 'corp']]
        ];
    }

    /**
     * @dataProvider invalidCallables
     * @expectedException \TypeError
     * @expectedExceptionMessageRegExp /must be.+callable/
     */
    public function test_exception_when_authenticator_is_not_callable($invalid_callable)
    {
        new TokenAuthentication([
            'authenticator' => $invalid_callable
        ]);
    }

    /**
     * @dataProvider invalidCallables
     * @expectedException \TypeError
     * @expectedExceptionMessageRegExp /must be.+callable/
     */
    public function test_exception_when_error_is_not_callable($invalid_callable)
    {
        new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'error' => $invalid_callable
        ]);
    }

    public function test_should_authenticate_when_matches_path()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth->process($request, new ResponseTokenHandler());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $response->getBody());
    }

    public function test_should_authenticate_when_middleware_applied_to_route_without_path_option()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
        ]);

        $handler = new ResponseTokenHandler();
        $responseFactory = AppFactory::determineResponseFactory();
        $callableResolver = new CallableResolver();
        $routeCollector = new RouteCollector($responseFactory, $callableResolver);
        $routeResolver = new RouteResolver($routeCollector);

        $route = $routeCollector->map(['GET'], '/api', [$handler, 'handle']);
        $routingResults = $routeResolver->computeRoutingResults(
            $request->getUri()->getPath(),
            $request->getMethod()
        );

        $request = $request
            ->withAttribute('routingResults', $routingResults)
            ->withAttribute('routeParser', $routeCollector->getRouteParser())
            ->withAttribute('route', $route);

        $response = $auth->process($request, $handler);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $response->getBody());
    }

    public function test_should_found_token_from_default_header()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth->process($request, new ResponseTokenHandler());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $response->getBody());
    }

    public function test_should_return_401_and_found_token()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token_invalid);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals(self::$token_invalid, json_decode((string) $response->getBody())->token);
    }

    public function test_should_return_401_and_found_token_when_applied_to_route_without_path_option()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token_invalid);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
        ]);

        $handler = new ResponseInitHandler();
        $responseFactory = AppFactory::determineResponseFactory();
        $callableResolver = new CallableResolver();
        $routeCollector = new RouteCollector($responseFactory, $callableResolver);
        $routeResolver = new RouteResolver($routeCollector);

        $route = $routeCollector->map(['GET'], '/api', [$handler, 'handle']);
        $routingResults = $routeResolver->computeRoutingResults(
            $request->getUri()->getPath(),
            $request->getMethod()
        );

        $request = $request
            ->withAttribute('routingResults', $routingResults)
            ->withAttribute('routeParser', $routeCollector->getRouteParser())
            ->withAttribute('route', $route);

        $response = $auth->process($request, $handler);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals(self::$token_invalid, json_decode((string) $response->getBody())->token);
    }

    public function test_should_return_401_and_not_found_token()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals();
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals(null, json_decode((string) $response->getBody())->token);
    }

    public function test_should_return_401_when_authorizator_return_false()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token_invalid);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'authenticatorWithReturnFalseWhenUnauthorized'],
            'path' => '/api'
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function test_should_found_token_from_custom_header()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('X-Token', 'Bearer ' . self::$token);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'header' => 'X-Token'
        ]);

        $response = $auth->process($request, new ResponseTokenHandler());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $response->getBody());
    }

    public function test_should_found_token_from_custom_header_with_custom_regex()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('X-Token', 'Custom ' . self::$token);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'header' => 'X-Token',
            'regex' => '/^Custom\s(.*)$/'
        ]);

        $response = $auth->process($request, new ResponseTokenHandler());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $response->getBody());
    }

    public function test_should_return_token_into_custom_attribute()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'attribute' => 'token'
        ]);

        $response = $auth->process($request, new ResponseTokenHandler('token'));

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, (string) $response->getBody());
    }

    public function test_should_found_token_from_cookie()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withCookieParams([
                'authorization' => self::$token
            ]);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth->process($request, new ResponseTokenHandler());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $response->getBody());
    }

    public function test_should_found_token_from_custom_cookie()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withCookieParams([
                'cookie-token' => self::$token
            ]);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'cookie' => 'cookie-token'
        ]);

        $response = $auth->process($request, new ResponseTokenHandler());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $response->getBody());
    }

    public function test_should_found_token_from_query_string_parameter()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withQueryParams([
                'token_parameter' => self::$token
            ]);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'parameter' => 'token_parameter'
        ]);

        $response = $auth->process($request, new ResponseTokenHandler());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $response->getBody());
    }

    public function test_should_return_attributes_setted_inside_authenticator()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth->process($request, new ResponseUsernameHandler());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$user['name'], (string) $response->getBody());
    }

    public function test_should_return_401_without_error_method()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token_invalid);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'error' => null
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEmpty((string) $response->getBody());
    }

    public function test_should_return_401_with_message()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token_invalid);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth->process($request, new ResponseTokenHandler());

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals(self::$wrong_token_message, json_decode((string) $response->getBody())->message);
    }

    public function test_should_return_401_with_custom_error()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token_invalid);
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $error = function(ServerRequestInterface $request, ResponseInterface $response, UnauthorizedExceptionInterface $e){

            $output = [
                'custom_message' => $e->getMessage()
            ];

            $response->getBody()->write(json_encode($output));
            return $response
                ->withHeader('Content-Type', 'application/json')
                ->withStatus(401);
        };

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'error' => $error
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals(self::$wrong_token_message, json_decode((string) $response->getBody())->custom_message);
    }

    public function test_should_return_401_when_not_using_https()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token);
        $uri = $request->getUri()->withScheme('http')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertRegExp('/Required HTTPS/', json_decode((string) $response->getBody())->message);
    }

    public function test_should_return_200_when_not_using_https_in_localhost()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token);
        $uri = $request->getUri()->withScheme('http')->withHost('localhost')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function test_should_return_200_when_not_using_https_with_relaxed()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token);
        $uri = $request->getUri()->withScheme('http')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'relaxed' => ['example.com']
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function test_should_return_200_with_secure_disabled()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals()
            ->withHeader('Authorization', 'Bearer ' . self::$token);
        $uri = $request->getUri()->withScheme('http')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'secure' => false
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function test_should_return_401_when_match_path()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals();
        $uri = $request->getUri()->withScheme('http')->withHost('example.com')->withPath('/api/users');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => ['/app', '/api', '/home']
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function test_should_return_401_when_match_path_with_trailing_slash()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals();
        $uri = $request->getUri()->withScheme('http')->withHost('example.com')->withPath('/api///');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function test_should_return_401_for_all_routes_when_path_empty()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals();
        $uri = $request->getUri()->withScheme('https')->withHost('example.com')->withPath('/api');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => ''
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function test_should_return_200_when_match_except()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals();
        $uri = $request->getUri()->withScheme('http')->withHost('example.com')->withPath('/api/users/status');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'except' => ['/api/tasks', '/api/users/']
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function test_should_return_200_when_not_match_path()
    {
        $request = (ServerRequestCreatorFactory::create())->createServerRequestFromGlobals();
        $uri = $request->getUri()->withScheme('http')->withHost('example.com')->withPath('/home');
        $request = $request->withUri($uri);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth->process($request, new ResponseInitHandler());

        $this->assertEquals(200, $response->getStatusCode());
    }
}
