<?php

use phpseclib4\Net\SFTP;

class SFTPChmodClass
{
    public function foo(SFTP $sftp): void
    {
        $sftp->chmod(0777, 'filename.remote');
        $sftp->chmod(0755, 'dirname', true);
    }
}

?>
-----
<?php

use phpseclib4\Net\SFTP;

class SFTPChmodClass
{
    public function foo(SFTP $sftp): void
    {
        $sftp->chmod('filename.remote', 0777);
        $sftp->chmod('dirname', 0755, true);
    }
}

?>
