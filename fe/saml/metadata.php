<?php
require_once __DIR__ . '/../vendor/autoload.php';

use OneLogin\Saml2\Settings;

try {
    $samlSettings = require '../saml_settings.php';
    $settings = new Settings($samlSettings, true);

    header('Content-Type: application/samlmetadata+xml');
    echo $settings->getSPMetadata();
} catch (Exception $e) {
    echo 'Metadata error: ' . $e->getMessage();
}
