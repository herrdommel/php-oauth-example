<?php

define('OAUTH_CLIENT_ID', getenv('CONFIG_OAUTH_CLIENT_ID'));
define('OAUTH_CLIENT_SECRET', getenv('CONFIG_OAUTH_CLIENT_SECRET'));
define('OAUTH_REDIRECT_URI', getenv('CONFIG_OAUTH_REDIRECT_URI'));
define('OAUTH_SCOPE', getenv('CONFIG_OAUTH_SCOPE'));
define('OAUTH_AUTHORIZATION_ENDPOINT', getenv('CONFIG_OAUTH_AUTHORIZATION_ENDPOINT'));
define('OAUTH_TOKEN_ENDPOINT', getenv('CONFIG_OAUTH_TOKEN_ENDPOINT'));
define('OAUTH_USER_ENDPOINT', getenv('CONFIG_OAUTH_USER_ENDPOINT'));

function base64url_decode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) {
        $data .= str_repeat('=', 4 - $remainder);
    }
    $data = strtr($data, '-_', '+/');
    return base64_decode($data);
}

function generateCodeVerifier($length = 128) {
    return rtrim(strtr(base64_encode(random_bytes($length)), '+/', '-_'), '=');
}

function generateCodeChallenge($verifier) {
    return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
}

function exchangeCode($code, $code_verifier) {
    $ch = curl_init(OAUTH_TOKEN_ENDPOINT);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
        CURLOPT_POSTFIELDS => http_build_query([
            'client_id'      => OAUTH_CLIENT_ID,
            'client_secret'  => OAUTH_CLIENT_SECRET,
            'code'           => $code,
            'redirect_uri'   => OAUTH_REDIRECT_URI,
            'grant_type'     => 'authorization_code',
            'code_verifier'  => $code_verifier
        ])
    ]);

    $response = curl_exec($ch);
    curl_close($ch);

    return json_decode($response, true);
}

function exchangeRefreshCode($refreshToken) {
    $credentials = base64_encode(OAUTH_CLIENT_ID . ':' . OAUTH_CLIENT_SECRET);

    $ch = curl_init(OAUTH_TOKEN_ENDPOINT);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => [
            'Authorization: Basic ' . $credentials,
            'Content-Type: application/x-www-form-urlencoded',
        ],
        CURLOPT_POSTFIELDS => http_build_query([
            'refresh_token'  => $refreshToken,
            'grant_type'     => 'refresh_token',
        ])
    ]);

    $response = curl_exec($ch);
    curl_close($ch);

    return json_decode($response, true);
}

function decodeIdToken($idToken) {
    $parts = explode('.', $idToken);
    list($encodedHeader, $encodedPayload, $encodedSignature) = $parts;
    $payload = json_decode(base64url_decode($encodedPayload), true);

    // Validate id token
    $validator = new JwtValidator($payload['iss'] . '/.well-known/openid-configuration');
    if (!$validator->verify($idToken)) {
        exit('Invalid ID token');
    }
}

?>
