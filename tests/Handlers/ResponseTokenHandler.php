<?php
declare(strict_types=1);

namespace Dyorg\Handlers;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Factory\AppFactory;

class ResponseTokenHandler implements RequestHandlerInterface
{
    protected $attributeName = 'authorization';

    public function __construct($attributeName = 'authorization')
    {
        if (is_string($attributeName) && !empty($attributeName)) {
            $this->attributeName = $attributeName;
        }
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $token = $request->getAttribute($this->attributeName);
        $response  = (AppFactory::determineResponseFactory())->createResponse();
        $response->getBody()->write($token);
        return $response;
    }
}
