<?php

use phpseclib3\File\X509;

class ReadingX509Class {
    function foo() {
        $x509 = new X509();
        $cert = $x509->loadX509('...');

        print_r($cert);
    }
}

?>
-----
<?php

use phpseclib4\File\X509;

class ReadingX509Class {
    function foo() {
        $cert = X509::load('...');

        print_r($cert);
    }
}

?>
