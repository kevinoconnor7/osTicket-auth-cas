<?php
return array(
  'id' =>             'auth:cas', # notrans
  'version' =>        '1.2.0',
  'name' =>           /* trans */ 'JASIG CAS Authentication',
  'author' =>         'Kevin O\'Connor',
  'description' =>    /* trans */ 'Provides a configurable authentication
  backend for authenticating staff and clients using CAS.',
  'url' =>            'https://www.github.com/kevinoconnor7/osTicket-auth-cas',
  'plugin' =>         'authentication.php:CasAuthPlugin',
  'requires' => array(
    "jasig/phpcas" => array(
      "version" => "1.3.8",
      "map" => array(
        "jasig/phpcas/source" => 'lib/jasig/phpcas',
        )
      ),
    ),
  );
?>
