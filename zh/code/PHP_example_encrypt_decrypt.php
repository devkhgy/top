<?php

// 商户安全码 (已 base64_encode 的 byte 资料)
$sh_key = '2KmMsAzSLqe9Q4P+h0hyWw==';
$key = base64_decode($sh_key);
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
 | 加解密
 |--------------------------------------------------------------------------
 | 生产环境请使用随机 iv 值以提高安全性
 |
 | API测试串接时可使用固定 iv 值: 1osdDsvHRXvVcVLFyzgI6w==
 | 正确加密後会得到加密字串: eyJpdiI6IjFvc2REc3ZIUlh2VmNWTEZ5emdJNnc9PSIsInZhbHVlIjoib2g2bEUwYThtMU4wWXB5b21mcDhUUmNzZ3QycGFNS0xuUzgzZzg1SXpsYUJGUVY1UEZ0VE85UWI2NmtRT0FRUXVoakpLMlUrOHBUL3duSXFibkJ1cUU2NHJhOTRPakdwOUluU2drUHVzSUk9In0=
*/

// 加密
$iv = random_bytes(16); // 随机 iv 值
$value = openssl_encrypt(json_encode($data, JSON_UNESCAPED_SLASHES), 'AES-128-CBC', $key, 0, $iv);
$encrypted = base64_encode(json_encode(['iv' => base64_encode($iv), 'value' => $value], JSON_UNESCAPED_SLASHES));
var_dump($encrypted);

// 解密
$payload = json_decode(base64_decode($encrypted), true);

if ( ! empty($payload['error_code'])) {
    // 取得错误码与对应信息
    $error_data = $payload['data'];
    var_dump($payload['error_code'], $error_data['message']);
    die();
}

$iv = base64_decode($payload['iv']);
$decrypted_string = openssl_decrypt($payload['value'], 'AES-128-CBC', $key, 0, $iv);
var_dump($decrypted_string);
