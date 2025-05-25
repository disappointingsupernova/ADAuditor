<?php
return [
    'strict' => true,
    'debug' => true,
    'sp' => [
        'entityId' => 'https://adaudit.domain.internal/saml/metadata.php',
        'assertionConsumerService' => [
            'url' => 'https://adaudit.domain.internal/saml/acs.php',
            'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        ],
        'singleLogoutService' => [
            'url' => 'https://adaudit.domain.internal/saml/sls.php',
            'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        ],
        'x509cert' => '',
        'privateKey' => '',
    ],
    'idp' => [
        'entityId' => 'https://sts.windows.net/<TENANT_ID>/',
        'singleSignOnService' => [
            'url' => 'https://login.microsoftonline.com/<TENANT_ID>/saml2',
        ],
        'singleLogoutService' => [
            'url' => 'https://login.microsoftonline.com/<TENANT_ID>/saml2',
        ],
        'x509cert' => '<REDACTED>',
    ],
];
