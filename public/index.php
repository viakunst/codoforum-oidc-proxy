<?php

use Steampixel\Route;
use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;

require dirname(__DIR__).'/sso.php';
require dirname(__DIR__).'/vendor/autoload.php';
$config = require_once dirname(__DIR__).'/config.php';

// configure the OpenID Connect client
session_start();
$oidc = new OpenIDConnectClient($config['oidc_provider'], $config['oidc_id'] ?? null, $config['oidc_secret'] ?? null, $config['oidc_issuer'] ?? null);
$oidc->addScope(['email', 'profile']);
$user = null;

// retrieve user through access token from session
if (isset($_SESSION['access_token'])) {
    $oidc->setAccessToken($_SESSION['access_token']);
    try {
        $user = $oidc->requestUserInfo();
    } catch (OpenIDConnectClientException $e) {
        // access token is expired, remove it
        $oidc->setAccessToken(null);
        unset($_SESSION['access_token']);
    }
}

// refresh access token if access token was expired
if (!$user && isset($_SESSION['refresh_token']) && $_SESSION['refresh_token']) {
    $oidc->refreshToken($_SESSION['refresh_token']);
    $_SESSION['access_token'] = $oidc->getAccessToken();
    $_SESSION['refresh_token'] = $oidc->getRefreshToken();
    try {
        $user = $oidc->requestUserInfo();
    } catch (OpenIDConnectClientException $e) {
        // connection has failed
        $oidc->setAccessToken(null);
        unset($_SESSION['access_token']);
        unset($_SESSION['refresh_token']);
        http_response_code(500);
        echo 'Problem with OIDC server';
        die;
    }
}

Route::add('/login', function() use ($config, $oidc) {
    $oidc->authenticate();
    $_SESSION['access_token'] = $oidc->getAccessToken();
    $_SESSION['refresh_token'] = $oidc->getRefreshToken();
    header('Location: '.$config['forum_redirect']);
});

Route::add('/logout', function() use ($config, $oidc) {
    if (isset($_SESSION['access_token'])) {
        $token = $_SESSION['access_token'];
        session_destroy();
        if (isset($config['oidc_signout'])) {
            header('Location: '.$config['oidc_signout']);
            die;
        }
        $oidc->signOut($token, $config['forum_redirect']);
    }
    header('Location: '.$config['forum_redirect']);
});

//output OIDC claims as JSON back to Codoforum
Route::add('/user', function() use ($config, $user) {
    if (!$user) {
        http_response_code(401); // Unauthorized
        die;
    }

    $sso = new \codoforum_sso($config);
    $sso->output_jsonp(array(
        'uid' => $user->sub,
        'name' => $user->name ?? '',
        'mail' => $user->email ?? '',
        'avatar' => $user->picture ?? '',
    ));
});

Route::run('/');
