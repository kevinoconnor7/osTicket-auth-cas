<?php

require_once INCLUDE_DIR.'class.plugin.php';
require_once 'config.php';

class CasAuthPlugin extends Plugin
{
  public $config_class = 'CasPluginConfig';

  public function bootstrap()
  {
    $config = $this->getConfig();

    $enabled = $config->get('cas-enabled');
    if (in_array($enabled, array('all', 'staff'))) {
      require_once 'cas.php';
      CasStaffAuthBackend::bootstrap($this->getConfig());
      StaffAuthenticationBackend::register(new CasStaffAuthBackend());
    }
    if (in_array($enabled, array('all', 'client'))) {
      require_once 'cas.php';
      CasClientAuthBackend::bootstrap($this->getConfig());
      UserAuthenticationBackend::register(new CasClientAuthBackend());
    }
  }
}

require_once INCLUDE_DIR.'UniversalClassLoader.php';
use Symfony\Component\ClassLoader\UniversalClassLoader_osTicket;

$loader = new UniversalClassLoader_osTicket();
$loader->registerNamespaceFallbacks(array(
  dirname(__file__).'/lib', ));
$loader->register();
