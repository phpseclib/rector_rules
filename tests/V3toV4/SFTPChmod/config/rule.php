<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use phpseclib\rectorRules\Rector\V3toV4\SFTPChmod;

return RectorConfig::configure()
  ->withRules([SFTPChmod::class]);
