<?php
require '../logging.php';
require_once __DIR__ . '/../vendor/autoload.php';

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Error;

session_start();

try {
    $samlSettings = require '../saml_settings.php';
    $auth = new Auth($samlSettings);

    $auth->processResponse();

    $errors = $auth->getErrors();
    if (!empty($errors)) {
        echo 'SAML response error: ' . implode(', ', $errors);
        exit;
    }

    if (!$auth->isAuthenticated()) {
        echo 'Not authenticated.';
        exit;
    }

    // Save attributes and user email to session
    $_SESSION['saml_user_data'] = $auth->getAttributes();
    $_SESSION['user_email'] = $auth->getAttribute('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress')[0] ?? null;

    // Restore original URL if available
    $redirectUrl = $_SESSION['post_login_redirect'] ?? '/index.php';
    unset($_SESSION['post_login_redirect']);
    $email = $_SESSION['user_email'];
    log_action($pdo, 'Login', 'User logged in', $email);

    header('Location: ' . $redirectUrl);
    exit;

} catch (Exception $e) {
    echo 'SAML Error: ' . $e->getMessage();
    exit;
}
