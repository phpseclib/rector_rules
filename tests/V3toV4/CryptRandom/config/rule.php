<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use phpseclib\rectorRules\Rector\V3toV4\CryptRandom;

return RectorConfig::configure()
  ->withRules([CryptRandom::class]);
