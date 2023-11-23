<?php

/**
 * User: Henny Krijnen
 * Date: 08-03-22 11:49
 * Copyright (c) eWarehousing Solutions
 */

namespace MiddlewareConnector\Requests\Variant;

use Saloon\Enums\Method;
use Saloon\Http\Request;

class GetVariantCollectionRequest extends Request
{
    protected Method $method = Method::GET;

    public function resolveEndpoint(): string
    {
        return 'wms/variants';
    }
}

