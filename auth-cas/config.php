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
        'configuration' => array('size'=>60, 'length'=>100),
        'hint' => $__('This maps to the "name" form field.'))),
      'cas-email-attribute-key' => new TextboxField(array(
        'label' => $__('E-mail attribute key'),
        'configuration' => array('size'=>60, 'length'=>100),
        'hint' => $__('This maps to the "email" form field.'))),
      'cas-username-form-field' => new ChoiceField(array(
        'label' => $__('Username attribute'),
        'default' => 'email',
        'choices' => array(
          'email' => $__('E-mail'),
          'username' => $__('Username'),
        ),
        'hint' => $__('This changes what attribute is passed to osTicket as the
          username, which affects both searching and provisioning. Assign a CAS attribute
          to the "username" form field in "Custom attributes" below to use that attribute
          instead of the CAS username.'))),
      'cas-custom-attributes' => new TextareaField(array(
        'label' => $__('Custom attributes'),
        'configuration' => array('cols'=>60, 'rows'=>5, 'length'=>1000,
          'html'=>false, 'placeholder'=>
            "sAMAccountName,adusername\nmobile,mobile"),
        'hint' => $__('Extra attributes that are not required to set up an
          account or sign in. Pass comma-delimited pairs of 2 in the form
          "claim-attribute,form-field", one pair per line.'))),
      'cas-single-sign-off' => new BooleanField(array(
        'label' => $__('Use single sign off'),
        'hint' => $__('Redirect to CAS sign out page when logging out of osTicket.'))),
      'cas-force-register' => new BooleanField(array(
        'label' => $__('Force client registration'),
        'hint' => $__('This is useful if you have public registration disabled.'))),
      'cas-enabled' => clone $modes);
  }

  function pre_save(&$config, &$errors) {
    list($__, $_N) = self::translate();

    // test CSV
    $attrs = $config['cas-custom-attributes'];
    if(empty(trim($attrs))) {
      $config['cas-custom-attributes'] = '';
    } else {
      $attrs = array_map('str_getcsv', str_getcsv($config['cas-custom-attributes'], "\n"));
      $username_field_choices = array('email', 'name');
      // iterate over rows of ["claim-attribute", "form-field"]
      for ($i = 0; $i < count($attrs); $i++) {
        $x = &$attrs[$i];
        if(count($x) != 2) {
          $err = $__('Each line should be in form "claim-attribute,form-field"');
        } elseif(in_array(trim($x[1]), $username_field_choices)) {
          $err = sprintf($__('Do not map to form field "%s", set it in the options above'), trim($x[1]));
        } else continue;
        $this->getForm()->getField('cas-custom-attributes')->addError(sprintf($__('Line %d: '), $i + 1) . $err);
        $errors['err'] = $__('Syntax error found in in custom attributes');
        break;
      }
    }

    global $msg;
    if (!$errors)
      $msg = $__('CAS configuration updated successfully');

    return !$errors;
  }
}
