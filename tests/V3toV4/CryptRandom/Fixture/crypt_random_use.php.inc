<?php

use phpseclib3\Crypt\Random;

class CryptRandomClass
{
    public function foo(): string
    {
        return Random::string(32);
    }
}

?>
-----
<?php

class CryptRandomClass
{
    public function foo(): string
    {
        return random_bytes(32);
    }
}

?>
