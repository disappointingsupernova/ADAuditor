<?php
require_once __DIR__ . '/vendor/autoload.php';

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Utils;

session_start();

$samlSettings = require 'saml_settings.php';
$auth = new Auth($samlSettings);

if (!isset($_SESSION['saml_user_data'])) {
    // Save the original requested URL before redirecting to login
    $_SESSION['post_login_redirect'] = $_SERVER['REQUEST_URI']; // Includes ?token=...
    $auth->login();
    exit;
}

// Initiate SSO if user not authenticated
if (!isset($_SESSION['saml_user_data'])) {
    $auth->login();
    exit;
}

// Store SAML attributes
$samlAttributes = $_SESSION['saml_user_data'];
$email = $samlAttributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'][0] ?? null;

// Optional: store this email globally
$_SESSION['user_email'] = $email;
