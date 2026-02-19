<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use phpseclib\rectorRules\Rector\V3toV4\CRL;
use phpseclib\rectorRules\Rector\V3toV4\HandleFileX509Imports;

return static function (RectorConfig $rectorConfig): void {
  $rectorConfig->rule(HandleFileX509Imports::class);
  $rectorConfig->rule(CRL::class);
};
