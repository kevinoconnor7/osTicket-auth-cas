JASIG CAS Authentication for osTicket
=====================================

Provides CAS authentication for agents and/or clients on osTicket.

Features
========
 - CAS extended attributes for user name and e-mail addresses.
 - Optionally appending a suffix to user names to allow mapping to e-mail addresses.
 - Login for both agents and clients (can be toggled for neither, either, or both).
 - Certificate validation (can be disabled for testing).
 - Auto creates clients if not already in osTicket.

Installing
==========

### Prebuilt

Download the auth-cas.phar from the [latest release](https://github.com/kevinoconnor7/osTicket-auth-cas/releases/latest)
and put it in your `includes/plugins` folder. From the admin panel go to
*Manage* --> *Plugins* --> *Add New Plugin* and select the plugin.

### From source

Follow the instructions to install [core-plugins](https://github.com/osTicket/core-plugins)
and then clone this repo into your `includes/plugns` folder. Then run
`php make.php hydrate` again.

Building
========

Make sure you have `make.php` from [core-plugins](https://github.com/osTicket/core-plugins)
and run `php make.php build auth-cas` to generate a phar package. This requires
that you have `phar.readonly = Off` in your php.ini file.

Testing
=======

If you don't have or don't wish to test against a real CAS instance you can
use [jasig-cas-quickdemo](https://github.com/forsetti/jasig-cas-quickdemo) to
spawn a demo server to utilize for testing.
