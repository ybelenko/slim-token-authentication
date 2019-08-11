<?php
declare(strict_types=1);

require_once '../vendor/autoload.php';

use Dyorg\TokenAuthentication;
use Dyorg\TokenAuthentication\Example\App\AuthService;
use Dyorg\TokenAuthentication\TokenSearch;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;

// Instantiate App
$app = AppFactory::create();

// Add error middleware
$app->addErrorMiddleware(true, true, true);

$authenticator = function(ServerRequestInterface &$request, TokenSearch $tokenSearch) {

    /**
     * Try find authorization token via header, parameters, cookie or attribute
     * If token not found, return response with status 401 (unauthorized)
     */
    $token = $tokenSearch->getToken($request);

    /**
     * Call authentication logic class
     */
    $auth = new AuthService();

    /**
     * Verify if token is valid on database
     * If token isn't valid, must throw an UnauthorizedExceptionInterface
     */
    $user = $auth->getUserByToken($token);

    /**
     * Set authenticated user at attibutes
     */
    $request = $request->withAttribute('authenticated_user', $user);

};

/**
 * Add token authentication middleware
 */
$app->add(new TokenAuthentication([
    'path' => '/restrict',
    'authenticator' => $authenticator,
    'relaxed' => [
        'localhost',
        '127.0.0.1',
        'slim-token-authentication.local'
    ]
]));

/**
 * Public route example
 */
$app->get('/', function($request, $response){
    $output = ['message' => 'It\'s a public area'];
    $response->getBody()->write(json_encode($output));
    return $response
        ->withHeader('Content-Type', 'application/json')
        ->withStatus(200);
});

/**
 * Restrict route example
 * Our token is "usertokensecret"
 */
$app->get('/restrict', function($request, $response){
    $output = ['message' => 'It\'s a restrict area. Token authentication works!'];
    $response->getBody()->write(json_encode($output));
    return $response
        ->withHeader('Content-Type', 'application/json')
        ->withStatus(200);
});

$app->run();