<?php

namespace PDAIUMA\SSOKeycloak;

use Illuminate\Support\ServiceProvider;
use PDAIUMA\SSOKeycloak\Services\SSOService;

class SSOKeycloakProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton('sso-keycloak', function ($app) {
            return new SSOService();
        });
    }

    public function boot()
    {
        
    }
}
