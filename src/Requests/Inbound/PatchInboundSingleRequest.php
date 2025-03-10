<?php

/*
 * User: Henny Krijnen
 * Date: 09-03-22 10:20
 * Copyright (c) eWarehousing Solutions
 */

namespace MiddlewareConnector\Requests\Inbound;

use Saloon\Contracts\Body\HasBody;
use Saloon\Enums\Method;
use Saloon\Http\Request;
use Saloon\Traits\Body\HasJsonBody;

class PatchInboundSingleRequest extends Request implements HasBody
{
    use HasJsonBody;

    protected Method $method = Method::PATCH;

    public function resolveEndpoint(): string
    {
        return 'wms/inbounds/' . $this->uuid;
    }

    public function __construct(
        public string $uuid,
        protected array $payload
    ) {
    }

    protected function defaultBody(): array
    {
        return $this->payload;
    }
}
