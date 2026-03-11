<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use phpseclib\rectorRules\Set\V2toV3Set;
use phpseclib\rectorRules\Set\V3toV4Set;

return RectorConfig::configure()
    // ->withSets([V2toV3Set::PATH]);
    ->withSets([V3toV4Set::PATH]);
