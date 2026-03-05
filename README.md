# rector_rules

Rector rules to upgrade a phpseclib v2.0 install to phpseclib v3.0 or
to upgrade a phpseclib v3.0 install to phpseclib v4.0.

## Overview

You can use [phpseclib2_compat](https://github.com/phpseclib/phpseclib2_compat) to make all your phpseclib v2.0 calls use phpseclib v3.0, internally, under the hood.
Or you can use this [Rector](https://getrector.com/) rule to upgrade your
phpseclib v2.0 calls to phpseclib v3.0 calls or your
phpseclib v3.0 calls to your phpseclib v4.0 calls.

## Installation

With [Composer](https://getcomposer.org/):

```bash
composer require phpseclib/rector_rules:~1.0
```

## Usage

Create a rector.php file with the following contents:

### v2 to v3 upgrade

```php
<?php
use Rector\Config\RectorConfig;
use phpseclib\rectorRules\Set\V2toV3Set;

return RectorConfig::configure()
    ->withSets([V2toV3Set::PATH]);
```

### v3 to v4 upgrade

```php
<?php
use Rector\Config\RectorConfig;
use phpseclib\rectorRules\Set\V3toV4Set;

return RectorConfig::configure()
    ->withSets([V3toV4Set::PATH]);
```

### Refactor

In the same directory where you created that file you can then run Rector by doing either of these commands:

```
vendor/bin/rector process src --dry-run
vendor/bin/rector process src
```
The files in the `src/` directory will either be full on modified or (in the case of `--dry-run`) the changes that would be made will be previewed.

## Running the tests

To run all Retor tests, run

```bash
vendor/bin/phpunit tests
```

To run all tests of a ruleset, add the name of it, like
```bash
vendor/bin/phpunit tests --filter V2toV3
```

To run all tests of a single rector rule, add --filter to the test command.

```bash
vendor/bin/phpunit tests --filter CustomRectorTest
```

### Test Fixtures

Next to the test case, there is `/Fixture` directory. It contains many test fixture files that verified the Rector rule work correctly in all possible cases.

There are 2 fixture formats:

A. `test_fixture.php.inc` - The Code Should Change

```php
<code before>
-----
<code after>
```

B. `skip_rule_test_fixture.php.inc` - The Code Should Be Skipped

```php
<code before>
```

## Rules

Details of the rules are in separate Readme files for [phpseclib v2.0 to phpseclib v3.0](./src/Rector/V2toV3/README.md) and [phpseclib v3.0 to phpseclib v4.0](./src/Rector/V3toV4/README.md).
