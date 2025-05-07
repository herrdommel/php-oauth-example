<?php

class JwtValidator
{
    private string $openidConfigUrl;
    private array $openidConfig;
    private array $jwks;

    public function __construct(string $openidConfigUrl)
    {
        $this->openidConfigUrl = $openidConfigUrl;
        $this->loadOpenIdConfig();
        $this->loadJwks();
    }

    private function loadOpenIdConfig(): void
    {
        $json = file_get_contents($this->openidConfigUrl);
        $this->openidConfig = json_decode($json, true);
    }

    private function loadJwks(): void
    {
        $jwksUri = $this->openidConfig['jwks_uri'] ?? null;
        if (!$jwksUri) {
            throw new Exception("jwks_uri not found in OpenID configuration");
        }
        $json = file_get_contents($jwksUri);
        $this->jwks = json_decode($json, true);
    }

    public function verify(string $jwt): bool
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new Exception('Invalid JWT format');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        $header = json_decode($this->base64urlDecode($encodedHeader), true);
        $kid = $header['kid'] ?? null;
        $alg = $header['alg'] ?? null;

        if (!$kid || !$alg) {
            throw new Exception('Missing kid or alg in JWT header');
        }

        $key = $this->findKeyByKid($kid);
        if (!$key) {
            throw new Exception("Public key with kid $kid not found");
        }

        if ($alg !== 'RS256') {
            throw new Exception("Unsupported algorithm: $alg");
        }

        $publicKeyPem = $this->buildPemFromModulusExponent($key['n'], $key['e']);
        $data = $encodedHeader . '.' . $encodedPayload;
        $signature = $this->base64urlDecode($encodedSignature);

        return openssl_verify($data, $signature, $publicKeyPem, OPENSSL_ALGO_SHA256) === 1;
    }

    private function findKeyByKid(string $kid): ?array
    {
        foreach ($this->jwks['keys'] as $key) {
            if ($key['kid'] === $kid) {
                return $key;
            }
        }
        return null;
    }

    private function base64urlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }

    private function buildPemFromModulusExponent(string $n, string $e): string
    {
        // Convert base64url -> binary -> ASN.1
        $modulus = $this->base64urlDecode($n);
        $exponent = $this->base64urlDecode($e);

        // ASN.1 encode for RSA public key (using raw DER encoding)
        $modulus = ltrim($modulus, "\0"); // Remove leading zero padding
        $components = [
            'modulus' => "\x02" . $this->encodeLength(strlen($modulus)) . $modulus,
            'exponent' => "\x02" . $this->encodeLength(strlen($exponent)) . $exponent
        ];

        $sequence = implode('', $components);
        $sequence = "\x30" . $this->encodeLength(strlen($sequence)) . $sequence;

        $bitString = "\x00" . $sequence;
        $bitString = "\x03" . $this->encodeLength(strlen($bitString)) . $bitString;

        $algorithmId = "\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00"; // rsaEncryption OID
        $subjectPublicKeyInfo = "\x30" . $this->encodeLength(strlen($algorithmId . $bitString)) . $algorithmId . $bitString;

        return "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n") .
            "-----END PUBLIC KEY-----\n";
    }

    private function encodeLength(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }
        $bytes = ltrim(pack('N', $length), "\x00");
        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
