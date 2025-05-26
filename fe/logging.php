<?php
require 'config.php';

function init_logging_table($pdo) {
    $pdo->exec("CREATE TABLE IF NOT EXISTS ui_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        log_type VARCHAR(50),
        log_message TEXT,
        email VARCHAR(255),
        ip_address VARCHAR(45),
        user_agent TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
}

function log_action($pdo, $type, $message, $email) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $stmt = $pdo->prepare("INSERT INTO ui_logs (log_type, log_message, email, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)");
    $stmt->execute([$type, $message, $email, $ip, $agent]);
}

init_logging_table($pdo);