<?php

use phpseclib4\Net\SFTP;

// Already in v4 order (path first) — should not be changed
class SFTPChmodSkipClass
{
    public function foo(SFTP $sftp): void
    {
        $sftp->chmod('filename.remote', 0777);
    }
}

?>
-----
<?php

use phpseclib4\Net\SFTP;

// Already in v4 order (path first) — should not be changed
class SFTPChmodSkipClass
{
    public function foo(SFTP $sftp): void
    {
        $sftp->chmod('filename.remote', 0777);
    }
}

?>
