<?php

namespace PDAIUMA\SSOKeycloak\Services;

use Exception;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Http;

class SSOService
{
    private $state;
    private $config;

    public function __construct()
    {
        $this->config = $this->getKeycloakConfig();
        $this->initializeState();
    }

    /**
     * Initializes the SSO state token.
     */
    private function initializeState()
    {
        if (!Session::has('_sso_state')) {
            $this->state = bin2hex(random_bytes(16));
            Session::put('_sso_state', $this->state);
        } else {
            $this->state = Session::get('_sso_state');
        }
    }

    /**
     * Logs messages with dynamic severity level.
     */
    private function log($message, $level = 'info')
    {
        Log::{$level}($message);
    }

    /**
     * Loads Keycloak configuration from the application's config file.
     */
    private function getKeycloakConfig()
    {
        return config('sso');
    }

    /**
     * Returns the base URL for Keycloak.
     */
    public function getBaseUrl()
    {
        return $this->config['base_url'];
    }

    /**
     * Returns the current SSO state.
     */
    public function getState()
    {
        return $this->state;
    }

    /**
     * Generates and returns the Keycloak login URL.
     */
    public function getLoginUrl()
    {
        $loginUrl = $this->getBaseUrl() . '/realms/' . $this->config['realm'] . '/protocol/openid-connect/auth?' . http_build_query([
            'client_id' => $this->config['client_id'],
            'redirect_uri' => $this->config['callback'],
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => $this->getState(),
        ]);

        $this->log("Login URL generated: $loginUrl");
        return $loginUrl;
    }

    /**
     * Authenticates the user with the authorization code and state.
     */
    public function authenticate($code, $state)
    {
        if ($state !== Session::get('_sso_state')) {
            return $this->errorResponse('Invalid state parameter. Potential CSRF attack.');
        }

        try {
            // Construct the token URL directly
            $tokenUrl = $this->getBaseUrl() . '/realms/' . $this->config['realm'] . '/protocol/openid-connect/token';
            $this->log("Requesting token from: $tokenUrl");

            // Make sure the data is formatted correctly for the request
            $response = $this->httpPost($tokenUrl, [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'client_id' => $this->config['client_id'],
                'client_secret' => $this->config['client_secret'],
                'redirect_uri' => $this->config['callback'],
            ]);

            $this->log("Token response: " . json_encode($response));

            if (isset($response['access_token'])) {
                $this->storeTokens($response);
                $this->log("Authentication successful for code: $code");

                // Directly fetching user info
                $userInfo = $this->getUserInfo();
                Session::put('user', $userInfo);
                Session::forget('_sso_state');

                return $this->successResponse(['user' => $userInfo]);
            }

            if (isset($response['error'])) {
                return $this->errorResponse('Error from token endpoint: ' . $response['error']);
            }

            return $this->errorResponse('Authentication failed. No access token received.');
        } catch (Exception $e) {
            return $this->exceptionResponse($e);
        }
    }

    /**
     * Retrieves user information directly using the userinfo endpoint.
     */
    public function getUserInfo()
    {
        $userinfoUrl = $this->getBaseUrl() . '/realms/' . $this->config['realm'] . '/protocol/openid-connect/userinfo';
        $accessToken = $this->getAccessToken();

        try {
            $response = $this->httpGet($userinfoUrl, $accessToken);
            if (isset($response['error'])) {
                $this->log('Error fetching user profile: ' . $response['error']);
                return null;
            }
            return $response;
        } catch (Exception $e) {
            return $this->exceptionResponse($e);
        }
    }

    /**
     * Logs the user out and redirects to the Keycloak logout endpoint.
     */
    public function logout()
    {
        Session::flush();

        $config = $this->getKeycloakConfig();
        $logoutUrl = $this->getBaseUrl() . '/realms/' . $config['realm'] . '/protocol/openid-connect/logout?' . http_build_query([
            'client_id' => $config['client_id'],
        ]);

        if (!headers_sent()) {
            header('Location: ' . $logoutUrl);
            exit();
        } else {
            throw new \Exception('Headers already sent. Unable to perform logout redirect.');
        }
    }

    /**
     * Returns the stored access token from the session.
     */
    public function getAccessToken()
    {
        return Session::get('access_token');
    }

    /**
     * Checks if the user is authenticated by introspecting the token.
     */
    public function isAuthenticated()
    {
        $accessToken = $this->getAccessToken();
        return $accessToken && $this->introspectToken($accessToken);
    }

    /**
     * Introspects the access token.
     */
    public function introspectToken($token)
    {
        try {
            $introspectionUrl = $this->getBaseUrl() . '/realms/' . $this->config['realm'] . '/protocol/openid-connect/token/introspect';
            $response = $this->httpPost($introspectionUrl, [
                'token' => $token,
                'client_id' => $this->config['client_id'],
                'client_secret' => $this->config['client_secret'],
            ]);

            return isset($response['active']) && $response['active'];
        } catch (Exception $e) {
            return $this->exceptionResponse($e);
        }
    }

    /**
     * Helper method to store tokens in the session.
     */
    private function storeTokens($response)
    {
        Session::put('access_token', $response['access_token']);
        Session::put('refresh_token', $response['refresh_token']);
    }

    /**
     * Executes an HTTP GET request with the given access token.
     */
    protected function httpGet($url, $accessToken)
    {
        return Http::withToken($accessToken)->get($url)->json();
    }

    /**
     * Executes an HTTP POST request.
     */
    private function httpPost($url, $data)
    {
        return Http::asForm()->post($url, $data)->json();
    }

    /**
     * Returns a success response.
     */
    private function successResponse($data = [])
    {
        return array_merge(['success' => true], $data);
    }

    /**
     * Returns an error response.
     */
    private function errorResponse($message)
    {
        $this->log($message, 'error');
        return ['success' => false, 'message' => $message];
    }

    /**
     * Handles exceptions and logs them.
     */
    private function exceptionResponse(Exception $e)
    {
        $this->log($e->getMessage(), 'error');
        return ['success' => false, 'message' => $e->getMessage()];
    }
}
