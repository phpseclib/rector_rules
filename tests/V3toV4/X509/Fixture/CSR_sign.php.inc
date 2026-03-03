<?php

$csr = $x509->signCSR();

?>
-----
<?php

$privKey->sign($csr);

?>
