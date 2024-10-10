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
        $this->app->alias('sso-keycloak', SSOService::class);
        $this->mergeConfigFrom(__DIR__.'/../config/sso.php', 'sso');
    }

    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/sso.php' => config_path('sso.php'),
        ], 'config');

        $this->app['router']->aliasMiddleware('sso.check', \PDAIUMA\SSOKeycloak\Middleware\SSOCheck::class);
    }
}
