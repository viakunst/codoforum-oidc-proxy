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
if (!$user && isset($_COOKIE['refresh_token'])) {
    $oidc->refreshToken($_COOKIE['refresh_token']);
    $_SESSION['access_token'] = $oidc->getAccessToken();
    store_refresh($oidc);
    try {
        $user = $oidc->requestUserInfo();
    } catch (OpenIDConnectClientException $e) {
        // connection has failed
        unset($_SESSION['access_token']);
        destroy_refresh();
        http_response_code(500);
        echo 'Problem with OIDC server';
        die;
    }
}

Route::add('/login', function() use ($config, $oidc) {
    $oidc->authenticate();
    $_SESSION['access_token'] = $oidc->getAccessToken();
    store_refresh($oidc);
    header('Location: '.$config['forum_redirect']);
});

Route::add('/logout', function() use ($config, $oidc) {
    destroy_refresh();
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

function store_refresh($oidc) {
    $refresh = $oidc->getRefreshToken();
    if (!$refresh) {
        destroy_refresh();
        return;
    }

    $expire = time()+60*60*24*30; // 30 days from now
    $domain = parse_url($oidc->getRedirectURL(), PHP_URL_HOST);
    setcookie('refresh_token', $refresh, $expire, '/', $domain, true, true);
}

function destroy_refresh() {
    if (isset($_COOKIE['refresh_token'])) {
        unset($_COOKIE['refresh_token']); 
        setcookie('refresh_token', "", time()-3600, '/');// one hour ago 
    }
}