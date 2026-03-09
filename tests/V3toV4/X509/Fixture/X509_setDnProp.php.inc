<?php

use phpseclib3\File\X509;

class SetDNPropClass {
  public static function SetDNProp() {
    $x509 = new X509();
    $x509->setDNProp('id-at-organizationName', 'phpseclib CA cert');
  }
}

?>
-----
<?php

class SetDNPropClass {
  public static function SetDNProp() {
    $x509->addDNProp('id-at-organizationName', 'phpseclib CA cert');
  }
}

?>
