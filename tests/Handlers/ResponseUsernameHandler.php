<?php
declare(strict_types=1);

namespace Dyorg\Handlers;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Factory\AppFactory;

class ResponseUsernameHandler implements RequestHandlerInterface
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $user_name = $request->getAttribute('user_from_inside_authenticator')['name'];
        $response  = (AppFactory::determineResponseFactory())->createResponse();
        $response->getBody()->write($user_name);
        return $response;
    }
}
