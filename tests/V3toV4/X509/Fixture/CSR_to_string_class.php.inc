<?php

class CSRStringClass {
  public static function CSRString() {
    $x509->saveCSR($csr);
  }
}

?>
-----
<?php

class CSRStringClass {
  public static function CSRString() {
    $csr->toString();
  }
}

?>
