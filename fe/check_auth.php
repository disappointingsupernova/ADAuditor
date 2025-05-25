<?php
require_once 'saml_auth.php';

// Now use the user email
$userEmail = $_SESSION['user_email'] ?? null;

if (!$userEmail) {
    echo "Authentication failed. Email not found.";
    exit;
}
