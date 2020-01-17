<?php

// $sh_key, the Merchant Key, is provided by OneWallet, which had encoded by base64 encoding. The merchat should store it in the persistent storage.
$sh_key = '2KmMsAzSLqe9Q4P+h0hyWw==';
$key = base64_decode($sh_key); // a byte value
$data = [
    'key1' => 'value1',
    'key2' => 'value2',
    'key3' => 'value3',
    'key4' => 'value4',
];

//$error_mapping = [
//  200 => 'Success',
//  403 => 'Permission error',
//  404 => 'Resource does not exist',
//  405 => 'Method not allowed',
//  422 => 'Verification error',
//  500 => 'Server error',
//];

/*
 |--------------------------------------------------------------------------
 | Encryption & Decryption
 |--------------------------------------------------------------------------
 | For more security, PLEASE use random IV in production
*/

// Encryption
$iv = random_bytes(16); // The random IV
$value = openssl_encrypt(json_encode($data, JSON_UNESCAPED_SLASHES), 'AES-128-CBC', $key, 0, $iv);
$encrypted = base64_encode(json_encode(['iv' => base64_encode($iv), 'value' => $value], JSON_UNESCAPED_SLASHES));
var_dump($encrypted);

// Decryption
$payload = json_decode(base64_decode($encrypted), true);

if ( ! empty($payload['error_code'])) {
    // Get the error_code and message
    $error_data = $payload['data'];
    var_dump($payload['error_code'], $error_data['message']);
    die();
}

$iv = base64_decode($payload['iv']);
$decrypted_string = openssl_decrypt($payload['value'], 'AES-128-CBC', $key, 0, $iv);
var_dump($decrypted_string);

