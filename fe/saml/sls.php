<?php
require_once __DIR__ . '/../vendor/autoload.php';

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Utils;

session_start();

$samlSettings = require '../saml_settings.php';
$auth = new Auth($samlSettings);

// Process the logout response/request
$auth->processSLO();

// Clear session after logout
$_SESSION = [];
session_destroy();

// Redirect somewhere after logout
header('Location: /');
exit;
