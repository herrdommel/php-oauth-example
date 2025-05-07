<?php
require_once 'util.php';
session_start();

$code_verifier = generateCodeVerifier();
$code_challenge = generateCodeChallenge($code_verifier);

$_SESSION['redirect'] = $_GET['r'] ?? 'profile.php';
$_SESSION['code_verifier'] = $code_verifier;
$_SESSION['oauth2state'] = $state = bin2hex(random_bytes(8));

$params = [
    'client_id'         => OAUTH_CLIENT_ID,
    'redirect_uri'      => OAUTH_REDIRECT_URI,
    'scope'             => OAUTH_SCOPE,
    'response_type'     => 'code',
    'state'             => $state,
    'code_challenge'    => $code_challenge,
    'code_challenge_method' => 'S256'
];

$authUrl = OAUTH_AUTHORIZATION_ENDPOINT . '?' . http_build_query($params);
header('Location: ' . $authUrl);
exit;
?>
