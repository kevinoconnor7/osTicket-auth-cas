<?php
require_once INCLUDE_DIR . 'class.plugin.php';

// Include CAS to ensure that we pull in the constants.
require_once(dirname(__file__).'/lib/jasig/phpcas/CAS.php');

class CasPluginConfig extends PluginConfig {

  // Provide compatibility function for versions of osTicket prior to
  // translation support (v1.9.4)
  function translate() {
    if (!method_exists('Plugin', 'translate')) {
      return array(
        function($x) { return $x; },
        function($x, $y, $n) { return $n != 1 ? $y : $x; },
        );
    }
    return Plugin::translate('auth-cas');
  }

  function getOptions() {
    list($__, $_N) = self::translate();
    $modes = new ChoiceField(array(
      'label' => $__('Authentication'),
      'default' => 'disabled',
      'choices' => array(
        'disabled' => $__('Disabled'),
        'staff' => $__('Agents Only'),
        'client' => $__('Clients Only'),
        'all' => $__('Agents and Clients'))));
    return array(
      'cas' => new SectionBreakField(array(
        'label' => $__('CAS Authentication'))),
      'cas-hostname' => new TextboxField(array(
        'label' => $__('Server Hostname'),
        'configuration' => array('size'=>60, 'length'=>100))),
      'cas-port' => new TextboxField(array(
        'label' => $__('Server Port'),
        'configuration' => array('size'=>10, 'length'=>8))),
      'cas-context' => new TextboxField(array(
        'label' => $__('Server Context'),
        'configuration' => array('size'=>60, 'length'=>100),
        'hint' => $__('This value is "/cas" for most installs.'))),
      'cas-version' => new ChoiceField(array(
        'label' => $__('CAS Protocol'),
        'default' => CAS_VERSION_2_0,
        'choices' => array(
          CAS_VERSION_2_0 => CAS_VERSION_2_0,
          CAS_VERSION_3_0 => CAS_VERSION_3_0,
        )
      )),
      'cas-ca-cert-path' => new TextboxField(array(
        'label' => $__('CA Cert Path'),
        'configuration' => array('size'=>60, 'length'=>100))),
      'cas-at-domain' => new TextboxField(array(
        'label' => $__('E-mail suffix'),
        'configuration' => array('size'=>60, 'length'=>100),
        'hint' => $__('Use this field if your CAS server does not
          report an e-mail attribute. ex: "domain.tld"'))),
      'cas-service-label' => new TextboxField(array(
        'label' => $__('Service label'),
        'configuration' => array('size'=>60, 'length'=>100),
        'hint' => $__('The text "Login with {label}" will appear on the login
            button. By default this is "CAS".'))),
      'cas-name-attribute-key' => new TextboxField(array(
        'label' => $__('Name attribute key'),
        'configuration' => array('size'=>60, 'length'=>100))),
      'cas-email-attribute-key' => new TextboxField(array(
        'label' => $__('E-mail attribute key'),
        'configuration' => array('size'=>60, 'length'=>100))),
      'cas-single-sign-off' => new BooleanField(array(
        'label' => $__('Use single sign off'))),
      'cas-force-register' => new BooleanField(array(
        'label' => $__('Force client registration'),
        'hint' => $__('This is useful if you have public registration disabled.'))),
      'cas-enabled' => clone $modes);
  }
}
