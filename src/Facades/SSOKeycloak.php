<?php

namespace PDAIUMA\SSOKeycloak\Facades;

use Illuminate\Support\Facades\Facade;

class SSOKeycloak extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'sso-keycloak';
    }
}
