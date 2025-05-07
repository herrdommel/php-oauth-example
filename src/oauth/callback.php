<?php
require_once 'util.php';
require_once 'jwt-validator.php';
session_start();

if (!isset($_GET['code'], $_GET['state']) || $_GET['state'] !== $_SESSION['oauth2state']) {
    exit('Invalid state or missing code');
}

$data = exchangeCode($_GET['code'], $_SESSION['code_verifier']);
$accessToken = $data['access_token'] ?? null;
$refreshToken = $data['refresh_token'] ?? null;
$idToken = $data['id_token'] ?? null;

if (!$accessToken || !$refreshToken || !$idToken) {
    exit('Error fetching tokens' . json_encode($data));
}

// Decode id_token
$payload = decodeIdToken($idToken);

// Store in session
$_SESSION['user'] = [
    'id' => $payload['uid'],
    'name' => $payload['name'],
    'email' => $payload['email'],
];
$_SESSION['tokens'] = [ // Must be stored in cache or DB
    'accessToken' => $accessToken,
    'refreshToken' => $refreshToken,
];

header('Location: ' . $_SESSION['redirect']);
exit;
?>
