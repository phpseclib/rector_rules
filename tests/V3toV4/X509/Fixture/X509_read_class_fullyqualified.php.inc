<?php

class ReadingX509Class {
  public static function ReadingX509() {
    $x509 = new \phpseclib3\File\X509();
    $cert = $x509->loadX509(file_get_contents('google.crt'));
  }
}

?>
-----
<?php

use phpseclib4\File\X509;

class ReadingX509Class {
  public static function ReadingX509() {
    $cert = X509::load(file_get_contents('google.crt'));
  }
}

?>
