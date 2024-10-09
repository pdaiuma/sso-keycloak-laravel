<?php

namespace PDAIUMA\SSOKeycloak\Middleware;

use Closure;
use Illuminate\Support\Facades\Session;
use PDAIUMA\SSOKeycloak\Services\SSOService;

class SSOCheck
{
    protected $ssoService;

    public function __construct(SSOService $ssoService)
    {
        $this->ssoService = $ssoService;
    }

    public function handle($request, Closure $next)
    {
        if (!Session::has('access_token')) {
            return redirect()->route('login');
        }

        $accessToken = Session::get('access_token');
        if (!$this->ssoService->introspectToken($accessToken)) {
            return redirect()->route('login');
        }

        return $next($request);
    }
}
