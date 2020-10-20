<?php
require_once(dirname(__file__).'/lib/jasig/phpcas/CAS.php');
define('CAS_DEBUG_MODE', false);

class CasAuth {
  private $config;

  function __construct($config) {
    $this->config = $config;
  }

  private static function buildClient($hostname, $port, $context, $version) {
    if (CAS_DEBUG_MODE) {
      phpCAS::setDebug(join(DIRECTORY_SEPARATOR, array(getenv('TEMP'), 'phpCAS.log')));
    }
    phpCAS::client(
      $version,
      $hostname,
      intval($port),
      $context,
      false);
    if (CAS_DEBUG_MODE) {
      phpCAS::setExtraCurlOption(CURLOPT_SSL_VERIFYHOST, 0);
      phpCAS::setExtraCurlOption(CURLOPT_SSL_VERIFYPEER, false);
    }
  }

  private static function buildClientFromConfig($config) {
    self::buildClient(
      $config->get('cas-hostname'),
      $config->get('cas-port'),
      $config->get('cas-context'),
      $config->get('cas-version')
    );
  }

  public function triggerAuth($service_url = null) {
    self::buildClientFromConfig($this->config);

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
      $this->setCustomFields();
    }
  }

  public static function signOut($config, $return_url = null) {
    self::buildClientFromConfig($config);
    unset($_SESSION[':cas']);

    if ($config->get('cas-single-sign-off')) {
      if (empty($return_url)) {
        phpCAS::logout();
      } else {
        phpCAS::logoutWithRedirectService($return_url);
      }
    }
  }

  // NOTE: User in this context is CAS user, not osTicket username;
  //       see getUsername() for osTicket username
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
        if (substr($this->config->get('cas-at-domain'), 0, 1) !== "@") {
          $email .= '@';
        }
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

  private function setCustomFields() {
    $custom = array();
    if(!empty($this->config->get('cas-custom-attributes'))) {
      // parse rows by splitting newlines, then map to columns
      $attrs = array_map('str_getcsv', str_getcsv($this->config->get('cas-custom-attributes'), "\n"));
      // iterate over rows of ["claim-attribute", "form-field"]
      foreach ($attrs as &$x) {
        // NOTE: fields are validated in config.php, only need to check if CAS has attr
        if(phpCAS::hasAttribute(trim($x[0]))) {
          $custom[trim($x[1])] = phpCAS::getAttribute(trim($x[0]));
        }
      }
    }
    $_SESSION[':cas']['custom'] = json_encode($custom);
  }

  public function getCustomFields() {
    return json_decode($_SESSION[':cas']['custom'], true, 2, JSON_THROW_ON_ERROR);
  }

  public function getProfile() {
    return array_merge($this->getCustomFields(), array(
        'email' => $this->getEmail(),
        'name' => $this->getName()
      ));
  }

  public function getUsernameField() {
    $field = $this->config->get('cas-username-form-field');
    if($field === null) {
      $field = 'email';
    }
    return $field;
  }

  // NOTE: Username in this context is osTicket username, not CAS user;
  //       see getUser() for CAS user
  public function getUsername() {
    $key = $this->getUsernameField();
    switch ($key) {
      case 'email':
        return $this->getEmail();
        break;
      case 'username':
        $info = $this->getCustomFields();
        if(array_key_exists('username', $info)) {
          return $info['username'];
        }
        return $this->getUser();
        break;
      default:
        // should never happen
        trigger_error("cas-username-form-field is malformed: expected value 'email' or 'username'", E_USER_ERROR);
    }
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
    if (isset($_SESSION[':cas'])) {
      if (($staff = StaffSession::lookup($this->cas->getUsername()))
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
    if ($cfg != null && !empty(trim($cfg->getUrl()))) {
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
      $username = $this->cas->getUsername();
      $acct = ClientAccount::lookupByUsername($username);
      $client = null;
      if ($acct && $acct->getId()) {
        $client = new ClientSession(new EndUser($acct->getUser()));
      }

      if (!$client) {
        $client = new ClientCreateRequest(
          $this, $username, $this->cas->getProfile());
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
    if ($cfg != null && !empty(trim($cfg->getUrl()))) {
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
