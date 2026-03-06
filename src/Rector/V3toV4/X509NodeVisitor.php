<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use PhpParser\Node;
use PhpParser\Node\Identifier;
use PhpParser\Node\Stmt;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\Variable;
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
  public const PRIV_KEY_OBJ = '';

  private const METHOD_TO_CLASS = [
    'loadX509' => 'phpseclib4\File\X509',
    'getDN' => 'phpseclib4\File\X509',
    'loadCSR'  => 'phpseclib4\File\CSR',
    'loadCRL'  => 'phpseclib4\File\CRL',
    'loadSPKAC'=> 'phpseclib4\File\CRL',
  ];

  public function __construct(
    private BetterNodeFinder $betterNodeFinder
  ) {}

  public function getNodeTypes(): array
  {
    return [FileNode::class];
  }

  public function enterNode(Node $node): ?Node
  {
    if (!$node instanceof FileNode) {
      return null;
    }
    $usedImports = [];

    $classes = $this->betterNodeFinder->findInstanceOf($node->stmts, Class_::class);
    foreach ($classes as $class) {
      $hasCsrMethodCall = false;
      $hasSetPrivateKey = false;
      $privKeyObj = null;

      $methodCalls = $this->betterNodeFinder->findInstanceOf($class, MethodCall::class);
      foreach ($methodCalls as $methodCall) {
        if (!$methodCall->name instanceof Identifier) {
          continue;
        }
        $methodName = $methodCall->name->toString();

        if ($methodName === 'setPrivateKey') {
          $hasSetPrivateKey = true;
          // Store the privateKey object to use it later for signing
          $arg = $methodCall->args[0]->value;
          if ($arg instanceof Variable && is_string($arg->name)) {
            $privKeyObj = $arg->name;
          }
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
        $class->setAttribute(self::PRIV_KEY_OBJ, $privKeyObj);

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
