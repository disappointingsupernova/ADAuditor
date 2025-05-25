<?php
// config.php

$copyright = "DisappointingSupernova"
$application_name = "AWS Access Review";

require 'vendor/autoload.php'; // Requires AWS SDK via Composer

use Aws\SecretsManager\SecretsManagerClient;
use Aws\Exception\AwsException;

$region = 'eu-west-2';  // Change as appropriate
$secretName = 'ad_auditor_mysql_secret';  // Change to your actual secret name

// Default (fallback) DB config if Secrets Manager is not used
$db_host = 'localhost';
$db_name = 'ad_audit';
$db_user = '<REDACTED>';
$db_pass = '<REDACTED>';

// Attempt to load from AWS Secrets Manager
try {

    $client = new SecretsManagerClient([
        'version' => 'latest',
        'region'  => $region
    ]);

    $result = $client->getSecretValue([
        'SecretId' => $secretName,
    ]);

    if (isset($result['SecretString'])) {
        $secret = json_decode($result['SecretString'], true);
        $db_host = $secret['host'] ?? $db_host;
        $db_name = $secret['database'] ?? $db_name;
        $db_user = $secret['user'] ?? $db_user;
        $db_pass = $secret['password'] ?? $db_pass;
    }

} catch (AwsException $e) {
    error_log("AWS Secrets Manager error: " . $e->getAwsErrorMessage());
    // Continue using default fallback credentials
}

// Connect to DB
try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
    ]);
} catch (PDOException $e) {
    http_response_code(500);
    echo "Database connection failed: " . htmlspecialchars($e->getMessage());
    exit;
}

$config = [
    'email' => [
        'mode'         => 'smtp',
        'from_address' => 'techops@internal.domain',
        'from_name'    => 'TechOps - AWS Access Review',
        'smtp_server'  => '127.0.0.1',
        'smtp_port'    => 25,
        'smtp_user'    => '',         // leave blank if not needed
        'smtp_password'=> '',         // leave blank if not needed
        'verify_tls' => false  // or true if you want verification enabled
    ],
    'notification_recipients' => [
        'techops@domain.com'
    ]
];
