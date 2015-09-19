<?php

require_once(dirname(__file__).'/lib/jasig/phpcas/CAS.php');

class CasAuth {
    private $config;

    function __construct($config) {
        $this->config = $config;
    }

    function triggerAuth($service_url = null) {
        $self = $this;
        phpCAS::client(
          CAS_VERSION_2_0,
          $this->config->get('cas-hostname'),
          intval($this->config->get('cas-port')),
          $this->config->get('cas-context')
        );

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
            $this->setAgent();
        }
    }

    function setUser() {
        $_SESSION[':cas']['user'] = phpCAS::getUser();
    }

    function getUser() {
        return $_SESSION[':cas']['user'];
    }

    function setEmail() {
        $email = $this->getUser();
        switch($this->config->get('attr-provider')) {
            case "cas" :
                if($this->config->get('email-attribute-key') !== null
                   && phpCAS::hasAttribute($this->config->get('email-attribute-key'))) {
                    $_SESSION[':cas']['email'] = phpCAS::getAttribute($this->config->get('email-attribute-key'));
                    break;
                }
            case "http" :
                if($this->config->get('email-attribute-key') !== null && $_SERVER['HTTP_'.strtoupper($this->config->get('email-attribute-key'))] !== null) {
                    $_SESSION[':cas']['email'] = $_SERVER['HTTP_'.strtoupper($this->config->get('email-attribute-key'))];
                    break;
                }
            case "none" :
                if($this->config->get('cas-at-domain') !== null) {
                    $email .= $this->config->get('cas-at-domain');
                }
            $_SESSION[':cas']['email'] = $email;
        }
    }

    function getEmail() {
        return $_SESSION[':cas']['email'];
    }

    function setName() {
        switch($this->config->get('attr-provider')) {
            case "cas" :
                if($this->config->get('name-attribute-key') !== null
                   && phpCAS::hasAttribute($this->config->get('name-attribute-key'))) {
                    $_SESSION[':cas']['name'] = phpCAS::getAttribute($this->config->get('name-attribute-key'));
                    break;
                }
            case "http" :
                if($this->config->get('name-attribute-key') !== null && $_SERVER['HTTP_'.strtoupper($this->config->get('name-attribute-key'))] !== null) {
                    $_SESSION[':cas']['name'] = $_SERVER['HTTP_'.strtoupper($this->config->get('name-attribute-key'))];
                    break;
                }
            $_SESSION[':cas']['name'] = $this->getUser();
        }
    }

    function getName() {
        return $_SESSION[':cas']['name'];
    }
    
    function setAgent() {
        switch($this->config->get('attr-provider')) {
            case "cas" :
                if($this->config->get('status-attribute-key') !== null
                   && phpCAS::hasAttribute($this->config->get('status-attribute-key'))) {
                    $_SESSION[':cas']['agent'] = phpCAS::getAttribute($this->config->get('status-attribute-key'))==$this->config->get('status-agent-value');
                    break;
                }
            case "http" :
                if($this->config->get('status-attribute-key') !== null && $_SERVER['HTTP_'.strtoupper($this->config->get('status-attribute-key'))] !== null) {
                    $_SESSION[':cas']['agent'] = $_SERVER['HTTP_'.strtoupper($this->config->get('status-attribute-key'))]==$this->config->get('status-agent-value');;
                    break;
                }
            $_SESSION[':cas']['agent'] = false ;
        }
    }
    
    function getAgent() {
        return $_SESSION[':cas']['agent'];
    }
    function getProfile() {
        return array(
            'email' => $this->getEmail(),
            'name' => $this->getName(),
            'agent' => $this->getAgent()
        );
    }
}

class CasStaffAuthBackend extends ExternalStaffAuthenticationBackend {
    static $id = "cas";
    static $name = /* trans */ "CAS";

    static $service_name = "CAS";

    var $config;

    function __construct($config) {
        $this->config = $config;
        $this->cas = new CasAuth($config);
    }

    function getName() {
         $config = $this->config;
         list($__, $_N) = $config::translate();
         return $__(static::$name);
     }

    function signOn() {
        if (isset($_SESSION[':cas']['user'])) {
            $staff = new StaffSession($this->cas->getEmail());
            if ($staff && $staff->getId()) {
                return $staff;
            } else {
                $_SESSION['_staff']['auth']['msg'] = 'Have your administrator create a local account';
            }
        }
    }

    static function signOut($user) {
        parent::signOut($user);
        unset($_SESSION[':cas']);
    }

    function getServiceUrl() {
      global $cfg;

      if (!$cfg) {
        return null;
      }
      return $cfg->getUrl() . "scp/login.php?do=ext&bk=cas";
    }

    function triggerAuth() {
        parent::triggerAuth();
        $cas = $this->cas->triggerAuth($this->getServiceUrl());
        Http::redirect("login.php");
    }
}

class CasClientAuthBackend extends ExternalUserAuthenticationBackend {
    static $id = "cas.client";
    static $name = /* trans */ "CAS";

    static $service_name = "CAS";

    function __construct($config) {
        $this->config = $config;
        $this->cas = new CasAuth($config);
    }

    function getName() {
         $config = $this->config;
         list($__, $_N) = $config::translate();
         return $__(static::$name);
     }

    function supportsInteractiveAuthentication() {
        return false;
    }

    function signOn() {
        // redirect agent to admin panel
        if($_SESSION[':cas']['agent']) {
            Http::redirect("scp/login.php");
        }
        
        if (isset($_SESSION[':cas']['user'])) {
            $acct = ClientAccount::lookupByUsername($this->cas->getEmail());
            $client = null;
            if ($acct && $acct->getId()) {
                $client = new ClientSession(new EndUser($acct->getUser()));
            }

            if ($client) {
                return $client;
            } else {
                return new ClientCreateRequest(
                  $this, $this->cas->getEmail(), $this->cas->getProfile());
            }
        }
    }

    static function signOut($user) {
        parent::signOut($user);
        unset($_SESSION[':cas']);
    }

    function getServiceUrl() {
      global $cfg;
      if (!$cfg) {
        return null;
      }
      return $cfg->getUrl() . "login.php?do=ext&bk=cas.client";
    }

    function triggerAuth() {
        parent::triggerAuth();
        $cas = $this->cas->triggerAuth($this->getServiceUrl());
        Http::redirect("login.php");
    }
}
