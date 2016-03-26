<?php
require_once(dirname(__file__).'/lib/jasig/phpcas/CAS.php');

class CasAuth {
  private $config;

  function __construct($config) {
    $this->config = $config;
  }

  private static function buildClient($hostname, $port, $context) {
    phpCAS::client(
      CAS_VERSION_2_0,
      $hostname,
      intval($port),
      $context,
      false);
  }

  public function triggerAuth($service_url = null) {
    self::buildClient(
      $this->config->get('cas-hostname'),
      $this->config->get('cas-port'),
      $this->config->get('cas-context'));

    // Force set the CAS service URL to the osTicket login page.
    if ($service_url) {
      phpCAS::setFixedServiceURL($service_url);
    }

    // Verify the CAS server's certificate, if configured.
    if($this->config->get('cas-ca-cert-path')) {
      phpCAS::setCasServerCACert($this->config->get('cas-ca-cert-path'));
    } else {
      phpCAS::setNoCasServerValidation();
    }

    // Trigger authentication and set the user fields when validated.
    if(!phpCAS::isAuthenticated()) {
      phpCAS::forceAuthentication();
    } else {
      $this->setUser();
      $this->setEmail();
      $this->setName();
    }
  }

  public static function signOut($config, $return_url = null) {
    self::buildClient(
      $config->get('cas-hostname'),
      $config->get('cas-port'),
      $config->get('cas-context'));

    unset($_SESSION[':cas']);

    if ($config->get('cas-single-sign-off')) {
      if (empty($return_url)) {
        phpCAS::logout();
      } else {
        phpCAS::logoutWithRedirectService($return_url);
      }
    }
  }

  public function setUser() {
    $_SESSION[':cas']['user'] = phpCAS::getUser();
  }

  public function getUser() {
    return $_SESSION[':cas']['user'];
  }

  private function setEmail() {
    if($this->config->get('cas-email-attribute-key') !== null && phpCAS::hasAttribute($this->config->get('cas-email-attribute-key'))) {
      $_SESSION[':cas']['email'] = phpCAS::getAttribute(
        $this->config->get('cas-email-attribute-key'));
    } else {
      $email = $this->getUser();
      if($this->config->get('cas-at-domain') !== null) {
        $email .= $this->config->get('cas-at-domain');
      }
      $_SESSION[':cas']['email'] = $email;
    }
  }

  public function getEmail() {
    return $_SESSION[':cas']['email'];
  }

  private function setName() {
    if($this->config->get('cas-name-attribute-key') !== null && phpCAS::hasAttribute($this->config->get('cas-name-attribute-key'))) {
      $_SESSION[':cas']['name'] = phpCAS::getAttribute(
        $this->config->get('cas-name-attribute-key'));
    } else {
      $_SESSION[':cas']['name'] = $this->getUser();
    }
  }

  public function getName() {
    return $_SESSION[':cas']['name'];
  }

  public function getProfile() {
    return array(
      'email' => $this->getEmail(),
      'name' => $this->getName());
  }
}

class CasStaffAuthBackend extends ExternalStaffAuthenticationBackend {
  static $id = "cas";
  static $name = /* trans */ "CAS";

  static $service_name = "CAS";

  private static $config;

  function __construct() {
    $this->cas = new CasAuth(self::$config);
    $customLabel = self::$config->get('cas-service-label');
    if (!empty($customLabel)) {
      self::$service_name = $customLabel;
    }
  }

  public static function bootstrap($config) {
    self::$config = $config;
  }

  function getName() {
    $config = self::$config;
    list($__, $_N) = $config::translate();
    return $__(static::$name);
  }

  function signOn() {
    if (isset($_SESSION[':cas']['user'])) {
      if (($staff = StaffSession::lookup($this->cas->getEmail()))
        && $staff->getId()) {
        if (!$staff instanceof StaffSession) {
          // osTicket <= v1.9.7 or so
          $staff = new StaffSession($staff->getId());
        }
        return $staff;
      } else {
        $_SESSION['_staff']['auth']['msg'] = 'Have your administrator create a local account';
      }
    }
  }

  static function signOut($user) {
    global $cfg;

    parent::signOut($user);

    $return_url = null;
    if ($cfg != null && !trim($cfg->getUrl())) {
      $return_url = $cfg->getUrl() . "scp/login.php";
    }
    CasAuth::signOut(self::$config, $return_url);
  }

  function getServiceUrl() {
    global $cfg;

    if (!$cfg) {
      return null;
    }
    return $cfg->getUrl() . "api/auth/ext";
  }

  function triggerAuth() {
    parent::triggerAuth();
    $cas = $this->cas->triggerAuth($this->getServiceUrl());
    Http::redirect(ROOT_PATH . "scp/login.php");
  }
}

class CasClientAuthBackend extends ExternalUserAuthenticationBackend {
  static $id = "cas.client";
  static $name = /* trans */ "CAS";

  static $service_name = "CAS";

  private static $config;

  function __construct() {
    $this->cas = new CasAuth(self::$config);

    $customLabel = self::$config->get('cas-service-label');
    if (!empty($customLabel)) {
      self::$service_name = $customLabel;
    }
  }

  public static function bootstrap($config) {
    self::$config = $config;
  }

  function getName() {
    $config = self::$config;
    list($__, $_N) = $config::translate();
    return $__(static::$name);
  }

  function supportsInteractiveAuthentication() {
    return false;
  }

  function signOn() {
    global $cfg;

    if (isset($_SESSION[':cas'])) {
      $acct = ClientAccount::lookupByUsername($this->cas->getEmail());
      $client = null;
      if ($acct && $acct->getId()) {
        $client = new ClientSession(new EndUser($acct->getUser()));
      }

      if (!$client) {
        $client = new ClientCreateRequest(
          $this, $this->cas->getEmail(), $this->cas->getProfile());
        if (!$cfg || !$cfg->isClientRegistrationEnabled() && self::$config->get('cas-force-register')) {
          $client = $client->attemptAutoRegister();
        }
      }
      return $client;
    }
  }

  static function signOut($user) {
    global $cfg;

    parent::signOut($user);

    $return_url = null;
    if ($cfg != null && !trim($cfg->getUrl())) {
      $return_url = $cfg->getUrl() . "login.php";
    }
    CasAuth::signOut(self::$config, $return_url);
  }

  function getServiceUrl() {
    global $cfg;
    if (!$cfg) {
      return null;
    }
    return $cfg->getUrl() . "api/auth/ext";
  }

  function triggerAuth() {
    parent::triggerAuth();
    $cas = $this->cas->triggerAuth($this->getServiceUrl());
    Http::redirect(ROOT_PATH . "login.php");
  }
}
