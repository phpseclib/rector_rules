<?php

use phpseclib3\File\X509;

class SetDNPropClass {
  public static function SetDNProp() {
    $x509 = new X509();
    $csr = $x509->loadCSR(file_get_contents('csr.csr'));
    $csr->setDNProp('id-at-organizationName', 'phpseclib CA cert');
  }
}

?>
-----
<?php

use phpseclib4\File\CSR;

class SetDNPropClass {
  public static function SetDNProp() {
    $csr = CSR::loadCSR(file_get_contents('csr.csr'));
    $csr->addDNProp('id-at-organizationName', 'phpseclib CA cert');
  }
}

?>
