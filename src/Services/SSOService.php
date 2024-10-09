<?php

namespace PDAIUMA\SSOKeycloak\Services;

use Exception;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Http;

class SSOService
{
    private $state;

    public function __construct()
    {
        if (!Session::has('_sso_state')) {
            $this->state = bin2hex(random_bytes(16));
            Session::put('_sso_state', $this->state);
        } else {
            $this->state = Session::get('_sso_state');
        }
    }

    private function log($message, $type = 'info')
    {
        Log::$type($message);
    }

    private function getKeycloakConfig()
    {
        return [
            'base_url' => env('KEYCLOAK_BASE_URL'),
            'realm' => env('KEYCLOAK_REALM'),
            'client_id' => env('KEYCLOAK_CLIENT_ID'),
            'client_secret' => env('KEYCLOAK_CLIENT_SECRET'),
            'callback' => env('KEYCLOAK_CALLBACK'),
        ];
    }

    public function getBaseUrl()
    {
        return $this->getKeycloakConfig()['base_url'];
    }

    public function getState()
    {
        return $this->state;
    }

    public function getOpenIDConfig()
    {
        $config = $this->getKeycloakConfig();
        $baseUrl = $config['base_url'];
        return [
            'issuer' => $baseUrl . '/' . $config['realm'],
            'authorization_endpoint' => $baseUrl . '/protocol/openid-connect/auth',
            'token_endpoint' => $baseUrl . '/protocol/openid-connect/token',
            'userinfo_endpoint' => $baseUrl . '/protocol/openid-connect/userinfo',
            'end_session_endpoint' => $baseUrl . '/protocol/openid-connect/logout',
            'jwks_uri' => $baseUrl . '/protocol/openid-connect/certs',
        ];
    }

    public function getLoginUrl()
    {
        $config = $this->getKeycloakConfig();
        $loginUrl = $this->getBaseUrl() . '/realms/' . $config['realm'] . '/protocol/openid-connect/auth?' . http_build_query([
            'client_id' => $config['client_id'],
            'redirect_uri' => $config['callback'],
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => $this->getState(),
        ]);

        $this->log("Login URL generated: $loginUrl");
        return $loginUrl;
    }

    public function authenticate($code, $state)
    {
        if ($state !== Session::get('_sso_state')) {
            return [
                'success' => false,
                'message' => 'Invalid state parameter. Potential CSRF attack.'
            ];
        }

        try {
            $config = $this->getKeycloakConfig();
            $tokenUrl = $this->getBaseUrl() . '/realms/' . $config['realm'] . '/protocol/openid-connect/token';
            $postData = [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'client_id' => $config['client_id'],
                'client_secret' => $config['client_secret'],
                'redirect_uri' => $config['callback'],
            ];

            $response = $this->httpPost($tokenUrl, $postData);

            if (isset($response['access_token'])) {
                Session::put('access_token', $response['access_token']);
                Session::put('refresh_token', $response['refresh_token']);
                $this->log("Authentication successful for code: $code");

                $userInfo = $this->getUserInfo();
                Session::put('user', $userInfo);
                
                Session::forget('_sso_state');

                return [
                    'success' => true,
                    'user' => $userInfo
                ];
            }

            $this->log("Authentication failed for code: $code", 'error');
            return [
                'success' => false,
                'message' => 'Authentication failed. No access token received.'
            ];

        } catch (Exception $e) {
            $this->log("Exception during authentication: " . $e->getMessage(), 'error');
            return [
                'success' => false,
                'message' => $e->getMessage()
            ];
        }
    }


    public function getUserInfo()
    {
        $userinfoUrl = $this->getBaseUrl() . '/realms/' . $this->getKeycloakConfig()['realm'] . '/protocol/openid-connect/userinfo';
        $accessToken = $this->getAccessToken();
        $response = $this->httpGet($userinfoUrl, $accessToken);
        
        if (isset($response['error'])) {
            $this->log('Error fetching user profile: ' . $response['error']);
            return null; 
        }

        return $response;
    }

    public function logout()
    {
        Session::flush(); 

        $config = $this->getKeycloakConfig();
        $logoutUrl = $this->getBaseUrl() . '/realms/' . $config['realm'] . '/protocol/openid-connect/logout?' . http_build_query([
            'client_id' => $config['client_id'],
            'redirect_uri' => $config['callback'],
        ]);

        header("Location: $logoutUrl");
        exit();
    }

    public function getAccessToken()
    {
        return Session::get('access_token');
    }

    public function isAuthenticated()
    {
        return $this->getAccessToken() && $this->introspectToken($this->getAccessToken());
    }

    public function introspectToken($token)
    {
        try {
            $config = $this->getKeycloakConfig();
            $response = Http::asForm()->post($config['base_url'] . '/realms/' . $config['realm'] . '/protocol/openid-connect/token/introspect', [
                'token' => $token,
                'client_id' => $config['client_id'],
                'client_secret' => $config['client_secret'],
            ]);

            return $response->successful() && isset($response['active']) && $response['active'];
        } catch (Exception $e) {
            $this->log("Exception during token introspection: " . $e->getMessage(), 'error');
            return false;
        }
    }

    protected function httpGet($url, $accessToken)
    {
        try {
            $response = Http::withToken($accessToken)->get($url);

            $this->log("HTTP GET request to $url with status: " . $response->status());

            if ($response->successful()) {
                return $response->json();
            } else {
                $this->log('Error fetching user profile: ' . $response->body());
                return ['error' => 'Unable to fetch user profile'];
            }
        } catch (Exception $e) {
            $this->log('Exception during HTTP GET: ' . $e->getMessage());
            throw new \Exception("HTTP GET error: " . $e->getMessage());
        }
    }

    private function httpPost($url, $data)
    {
        $response = Http::asForm()->post($url, $data);
        return $response->json(); 
    }
}
