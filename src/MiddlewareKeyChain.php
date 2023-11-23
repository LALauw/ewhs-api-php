<?php

/**
 * User: Henny Krijnen
 * Date: 08-03-22 11:49
 * Copyright (c) eWarehousing Solutions
 */

namespace MiddlewareConnector;

use DateTime;
use MiddlewareConnector\Requests\Auth\PostAuthTokenRequest;
use MiddlewareConnector\Requests\Auth\PostRefreshTokenRequest;
use Saloon\Http\PendingRequest;
use MiddlewareConnector\Exceptions\AuthenticationException;

class MiddlewareKeyChain implements \Saloon\Contracts\Authenticator
{
    private ?DateTime $tokenExpiresAt = null;
    private ?string $token = null;

    public function __construct(
        protected ?string $username = null,
        protected ?string $password = null,
        protected ?string $refreshToken = null,
        protected ?string $customerCode = null,
        protected ?string $wmsCode = null,
    ) {
    }

    /**
     * Called every request
     *
     * @param  PendingRequest $request
     * @return void
     * @throws AuthenticationException
     */
    public function boot(PendingRequest $request): void
    {
        var_dump('asd');
        exit();
        if ($this->tokenExpiresAt == null || $this->tokenExpiresAt < new DateTime()) {
            $this->fetchToken($request);
        }

        if ($this->token) {
            $request->withTokenAuth($this->token);
        }
    }

    /**
     * Fetch token logic
     *
     * @param PendingRequest $request
     *
     * @return void
     *
     * @throws AuthenticationException
     */
    private function fetchToken(PendingRequest $request): void
    {
        exit();
        echo "hello \n";
//        if (!$this->shouldFetch($request)) {
//            return;
//        }

        $connector = $request->getConnector();

        if ($this->refreshToken === null) {
            $auth = $connector->send(new PostAuthTokenRequest(
                username: $this->username,
                password: $this->password,
            ));

            if ($auth->status() !== 200) {
                throw new AuthenticationException('Could not fetch new token!');
            }
        } else {

            $auth = $connector->send(new PostRefreshTokenRequest(
                refreshToken: $this->refreshToken,
            ));


            if ($auth->status() !== 200) {
                throw new AuthenticationException('Could not refresh token!');
            }
        }

        $dateTime = new DateTime();
        $dateTime->modify('+45 minutes');
        $this->tokenExpiresAt = $dateTime;
        $this->token = $auth->json()['token'] ?? null;
        $this->refreshToken = $auth->json()['refresh_token'] ?? null;
    }

    /**
     * Validates if we need to auth for current route
     *
     * @param  PendingRequest $request
     * @return bool
     */
    private function shouldFetch(PendingRequest $request): bool
    {
        if (
            $request->getUrl() !== (new PostAuthTokenRequest('ignore', 'ignore'))->resolveEndpoint()
            && $request->getUrl() !== (new PostRefreshTokenRequest('ignore'))->resolveEndpoint()
        ) {
            return true;
        }

        return false;
    }

    public function set(PendingRequest $pendingRequest): void
    {
        $pendingRequest->headers()->add('Accept', '*/*');
        $pendingRequest->headers()->add('Content-Type', 'application/json');
        $pendingRequest->headers()->add('User-Agent', 'eWarehousingSolutions/2.0.0');
        $pendingRequest->headers()->add('X-Customer-Code', $this->customerCode);
        $pendingRequest->headers()->add('X-WMS-Code', $this->wmsCode);
    }
}
