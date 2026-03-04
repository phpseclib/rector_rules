<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use PhpParser\Node;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Name;
use PhpParser\Node\Name\FullyQualified;
use Rector\PhpParser\Node\FileNode;
use Rector\PhpParser\Node\BetterNodeFinder;

use PhpParser\NodeVisitorAbstract;
use Rector\Contract\PhpParser\DecoratingNodeVisitorInterface;

use phpseclib\rectorRules\Rector\V3toV4\HandleFileX509Imports;

final class X509NodeVisitor extends NodeVisitorAbstract implements DecoratingNodeVisitorInterface
{
  public const IS_CSR = 'is_csr';

  const METHOD_TO_CLASS = [
    'loadX509' => 'phpseclib4\File\X509',
    'getDN' => 'phpseclib4\File\X509',
    'loadCSR'  => 'phpseclib4\File\CSR',
    'loadCRL'  => 'phpseclib4\File\CRL',
    'loadSPKAC'=> 'phpseclib4\File\CRL',
  ];

  public function __construct(
    private BetterNodeFinder $betterNodeFinder
  ) {}

  public function enterNode(Node $node)
  {
    if (!$node instanceof FileNode) {
      return null;
    }
    $usedImports = [];

    $classes = $this->betterNodeFinder->findInstanceOf($node->stmts, Class_::class);
    foreach ($classes as $class) {
      $hasCsrMethodCall = false;
      $hasSetPrivateKey = false;

      $methodCalls = $this->betterNodeFinder->findInstanceOf($class, MethodCall::class);
      foreach ($methodCalls as $methodCall) {
        $methodName = $methodCall->name instanceof Node\Identifier
          ? $methodCall->name->toString()
          : null;

        if ($methodName === null) {
          continue;
        }

        if ($methodName === 'setPrivateKey') {
          $hasSetPrivateKey = true;
        }

        if (in_array($methodName, ['loadCSR','signCSR','saveCSR'], true)) {
          $hasCsrMethodCall = true;
        }

        if (isset(self::METHOD_TO_CLASS[$methodName])) {
          $usedImports[self::METHOD_TO_CLASS[$methodName]] = true;
        }
      }
      // Set isCSR attribute on Class_
      if ($hasCsrMethodCall) {
        $class->setAttribute(self::IS_CSR, true);
      }
      // setPrivateKey can be used by CSR and CRL
      if ($hasSetPrivateKey) {
        if ($class->getAttribute(self::IS_CSR, false)) {
          $usedImports['phpseclib4\File\CSR'] = true;
        } else {
          $usedImports['phpseclib4\File\CRL'] = true;
        }
      }
    }
    // set usedImports on the FileNode
    $node->setAttribute('usedImports', $usedImports);
    return null;
  }
}
