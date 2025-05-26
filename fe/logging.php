<?php

require 'config.php';

function init_logging_table($pdo) {
    $pdo->exec("CREATE TABLE IF NOT EXISTS ui_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        log_type VARCHAR(50),
        log_message TEXT,
        email VARCHAR(255),
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
}

function log_action($pdo, $type, $message, $email) {
    $stmt = $pdo->prepare("INSERT INTO ui_logs (log_type, log_message, email) VALUES (?, ?, ?)");
    $stmt->execute([$type, $message, $email]);
}

init_logging_table($pdo);