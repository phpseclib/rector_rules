<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Name\FullyQualified;
use PhpParser\Node\UseItem;
use Rector\Rector\AbstractRector;

/**
 * Renames the phpseclib3\ root namespace to phpseclib4\ everywhere — in use
 * statements and in fully-qualified names used inline.
 *
 * Short names (e.g. RSA in "use phpseclib3\Crypt\RSA; new RSA()") are left
 * alone: renaming the use statement is sufficient for them to resolve correctly.
 *
 * Classes deliberately skipped here (handled by dedicated rules):
 *   - phpseclib3\File\X509  → split into X509 / CSR / CRL / SPKAC (X509 rule)
 *   - phpseclib3\Crypt\Random → removed; replaced by random_bytes() (CryptRandom rule)
 */
final class Namespace_ extends AbstractRector
{
  private const SKIP = [
    'phpseclib3\File\X509',
    'phpseclib3\Crypt\Random',
  ];

  public function getNodeTypes(): array
  {
    return [UseItem::class, FullyQualified::class];
  }

  public function refactor(Node $node): ?Node
  {
    if ($node instanceof UseItem) {
      $name = $node->name->toString();
      if (!str_starts_with($name, 'phpseclib3\\')) {
        return null;
      }
      if (in_array($name, self::SKIP, true)) {
        return null;
      }
      $node->name = new Name('phpseclib4\\' . substr($name, strlen('phpseclib3\\')));
      return $node;
    }

    // FullyQualified — only rename if written explicitly in source (not resolved from a short name).
    // Resolved short names occupy file-character span of the alias only (e.g. 4 chars for "SFTP"),
    // while explicit FQNs span the full string including the leading backslash.
    $name = $node->toString();
    if (!str_starts_with($name, 'phpseclib3\\')) {
      return null;
    }
    if (in_array($name, self::SKIP, true)) {
      return null;
    }
    $expectedSpan = strlen('\\' . $name);
    $actualSpan = $node->getEndFilePos() - $node->getStartFilePos() + 1;
    if ($actualSpan !== $expectedSpan) {
      // Span doesn't match the full FQN — this was resolved from a short name via a use import.
      return null;
    }

    return new FullyQualified('phpseclib4\\' . substr($name, strlen('phpseclib3\\')));
  }
}
