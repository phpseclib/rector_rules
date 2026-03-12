<?php

use phpseclib4\File\X509;

class ReadingX509Class {
  public static function foo() {
    $x509 = new \phpseclib3\File\X509();
    $foo = $x509->validateDate();
  }
}

?>
-----
<?php

use phpseclib4\File\X509;

class ReadingX509Class {
  public static function foo()
  {
  }
}

?>
