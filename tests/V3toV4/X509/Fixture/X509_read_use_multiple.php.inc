<?php

use phpseclib3\File\X509;

$x509 = new X509();
$cert = $x509->loadX509('...');

$foo = new X509();
$bar = $foo->loadX509('...');

?>
-----
<?php

use phpseclib4\File\X509;

$cert = X509::load('...');
$bar = X509::load('...');

?>
