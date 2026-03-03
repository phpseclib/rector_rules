<?php

class CSRSignClass {
  public static function CSRSign() {
    $csr = $x509->signCSR();
  }
}

?>
-----
<?php

class CSRSignClass {
  public static function CSRSign() {
    $privKey->sign($csr);
  }
}

?>
