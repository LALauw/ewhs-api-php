<?php

/*
 * User: Henny Krijnen
 * Date: 09-03-22 10:20
 * Copyright (c) eWarehousing Solutions
 */

namespace MiddlewareConnector\Requests\Order;

use Saloon\Enums\Method;
use Saloon\Http\Request;

class GetOrderDocumentSingleRequest extends Request
{
    protected Method $method = Method::GET;

    public function resolveEndpoint(): string
    {
        return 'wms/orders/' . $this->uuid . '/documents' . $this->documentUuid;
    }

    public function __construct(
        public string $uuid,
        public string $documentUuid,
    ) {
    }
}
