<?php
require_once 'util.php';
require_once 'jwt-validator.php';
session_start();

sleep(1);
// Refresh access token with id token
$data = exchangeRefreshCode($_SESSION['tokens']['refreshToken']);
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

// Get some user data with access token
$ch = curl_init(OAUTH_USER_ENDPOINT);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => [
        "Authorization: Bearer " . $_SESSION['tokens']['accessToken'],
        'User-Agent: PHP-OAuth-App'
    ]
]);

$userData = curl_exec($ch);
curl_close($ch);

$user = json_decode($userData, true);
echo "<pre>";
print_r($user);
echo "</pre>";

?>
