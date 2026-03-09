<?php

use phpseclib3\File\X509;

class GetSubjectDNClass {
  public static function GetSubjectDN() {
    $x509->getDN(...);
  }
}

?>
-----
<?php

use phpseclib4\File\X509;

class GetSubjectDNClass {
  public static function GetSubjectDN() {
    $x509->getSubjectDN(...);
  }
}

?>
