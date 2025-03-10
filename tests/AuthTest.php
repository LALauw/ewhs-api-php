<?php

/*
 * User: Henny Krijnen
 * Date: 08-03-22 11:49
 * Copyright (c) eWarehousing Solutions
 */

namespace MiddlewareConnector\Tests;

use MiddlewareConnector\Exceptions\AuthenticationException;
use MiddlewareConnector\MiddlewareConnector;
use MiddlewareConnector\Requests\Article\GetArticleCollectionRequest;
use MiddlewareConnector\Requests\Article\GetArticleSingleRequest;
use MiddlewareConnector\Requests\Auth\PostAuthTokenRequest;
use MiddlewareConnector\Requests\Auth\PostRefreshTokenRequest;
use PHPUnit\Framework\TestCase;
use Saloon\Http\Faking\MockClient;
use Saloon\Http\Faking\MockResponse;

class AuthTest extends TestCase
{
    public function testRequestNewTokenWithUsernamePassword(): void
    {
        $mockClient = new MockClient([
            GetArticleCollectionRequest::class => new MockResponse([['name' => 'test']], 200),
            PostAuthTokenRequest::class => new MockResponse(['token' => 'MY_TEST_TOKEN', 'refresh_token' => ''], 200),
        ]);

        $connector = MiddlewareConnector::create(
            'username',
            'password',
            'wmsCode',
            'CustomerCode',
            MiddlewareConnector::BASE_URL_EU_DEV,
        );

        $connector->withMockClient($mockClient);

        $request = $connector->send(new getArticleCollectionRequest());
        $this->assertSame(200, $request->status());
    }

//    public function testRequestNewTokenWithUsernamePasswordFailed(): void
//    {
//        $mockClient = new MockClient([
//            GetArticleCollectionRequest::class => MockResponse::make([['name' => 'test']], 200),
//            PostAuthTokenRequest::class => MockResponse::make(['token' => 'MY_TEST_TOKEN', 'refresh_token' => ''], 500),
//        ]);
//
//        $this->expectException(AuthenticationException::class);
//        $this->expectExceptionMessage('Could not fetch new token!');
//        $connector = MiddlewareConnector::create(
//            'username',
//            'password',
//            'wmsCode',
//            'CustomerCode',
//            MiddlewareConnector::BASE_URL_EU_DEV,
//        );
//        $connector->withMockClient($mockClient);
//
//        $response = $connector->send(new getArticleCollectionRequest());
//        $this->assertSame(500, $response->status());
//    }

    public function testRequestNewTokenWithRefreshToken(): void
    {
        $mockClient = new MockClient([
            GetArticleCollectionRequest::class => MockResponse::make([['name' => 'test']], 200),
            PostRefreshTokenRequest::class => MockResponse::make([
                'token' => 'MY_TEST_TOKEN', 'refresh_token' => ''], 200),
        ]);


        $connector = MiddlewareConnector::createWithRefreshToken(
            'refreshToken',
            'wmsCode',
            'CustomerCode',
            MiddlewareConnector::BASE_URL_EU_DEV,
        );

        $connector->withMockClient($mockClient);

        $response = $connector->send(new getArticleCollectionRequest());
        $this->assertSame(200, $response->status());
    }

    // TODO: check this test
//    public function testRequestNewTokenWithRefreshTokenFailed(): void
//    {
//        $mockClient = new MockClient([
//            GetArticleCollectionRequest::class => MockResponse::make([['name' => 'test']], 500),
//            PostRefreshTokenRequest::class => MockResponse::make(
//                ['token' => 'MY_TEST_TOKEN', 'refresh_token' => ''],
//                500
//            ),
//        ]);
//
//        $this->expectException(AuthenticationException::class);
//        $this->expectExceptionMessage('Could not refresh token!');
//
//        $connector = MiddlewareConnector::createWithRefreshToken(
//            'refreshToken',
//            'wmsCode',
//            'CustomerCode',
//            MiddlewareConnector::BASE_URL_EU_DEV,
//        )->withMockClient($mockClient);
//
//        $response = $connector->send(new GetArticleCollectionRequest(), $mockClient);
//        var_dump($response->status());
//        $this->assertSame(500, $response->status());
//    }

//    public function testRefreshTokenOnlyFetchedWhenExpired(): void
//    {
//        $mockClient = new MockClient([
//            GetArticleCollectionRequest::class => new MockResponse([['name' => 'test']], 200),
//            PostRefreshTokenRequest::class => new MockResponse(['token' => 'MY_TEST_TOKEN', 'refresh_token' => ''], 200),
//        ]);
//
//        $connector = MiddlewareConnector::createWithRefreshToken(
//            'refreshToken',
//            'wmsCode',
//            'CustomerCode',
//            MiddlewareConnector::BASE_URL_EU_DEV,
//        )->withMockClient($mockClient);
//
//
//
//        $response = $connector->getArticleCollectionRequest()->send($mockClient);
//        $this->assertSame(200, $response->status());
//        $mockClient->assertSentCount(2); // expect 1 auth call and 1 article call
//
//        $connector->getArticleCollectionRequest()->send($mockClient);
//        $mockClient->assertSentCount(3); // don't expect another auth call
//    }
}
