<?php

use phpseclib3\File\X509;

class ReadSpkacClass {
  public static function foo() {
    $x509 = new X509();
    $spkac = $x509->loadSPKAC(file_get_contents('spkac.txt'));
  }
}

?>
-----
<?php

use phpseclib4\File\CRL;

class ReadSpkacClass {
  public static function foo() {
    $spkac = CRL::loadCRL(file_get_contents('spkac.txt'));
  }
}
