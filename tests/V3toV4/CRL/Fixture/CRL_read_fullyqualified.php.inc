<?php

$x509 = new \phpseclib3\File\X509();
$crl = $x509->loadCRL(file_get_contents('crl.bin'));

print_r($crl);

?>
-----
<?php

use phpseclib4\File\CRL;


$crl = CRL::loadCRL(file_get_contents('crl.bin'));

print_r($crl);

?>