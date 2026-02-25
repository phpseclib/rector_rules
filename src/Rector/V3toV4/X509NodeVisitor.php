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
use Rector\PhpParser\Node\FileNode;

use PhpParser\NodeVisitorAbstract;
use Rector\Contract\PhpParser\DecoratingNodeVisitorInterface;

use phpseclib\rectorRules\Rector\V3toV4\HandleFileX509Imports;

final class X509NodeVisitor extends NodeVisitorAbstract implements DecoratingNodeVisitorInterface
{
  public const IS_CSR = 'is_csr';
  private array $usedImports = [];

  public function enterNode(Node $node)
  {
    if (!$node instanceof FileNode) {
      return null;
    }

    // loop filenodes to get classes
    foreach ($node->stmts as $class) {
      if (!$class instanceof Class_) {
        continue;
      }
      $hasCsrMethodCall = false;

      // loop classes to get ClassMethods
      foreach ($class->stmts as $stmt) {
        if (!$stmt instanceof ClassMethod) {
          continue;
        }
        // loop ClassMethods to get node
        foreach ($stmt->stmts ?? [] as $innerNnode) {
          if($innerNnode instanceof Expression && $innerNnode->expr instanceof MethodCall) {
            $methodName = $innerNnode->expr->name->name;
            if(in_array($methodName, ['setDNProp', 'signCSR', 'saveCSR'], true)) {
              $hasCsrMethodCall = true;
              $this->usedImports['phpseclib4\File\CSR'] = true;
              break 2;
            }

            // Track used imports for method calls
            if ($methodName !== null && isset(HandleFileX509Imports::METHOD_TO_CLASS[$methodName])) {
                [$targetClass,] = HandleFileX509Imports::METHOD_TO_CLASS[$methodName];
                $this->usedImports[$targetClass] = true;
            }
          }
        }
        // Set the attribute on the class itself
        if ($hasCsrMethodCall) {
          $node->setAttribute(self::IS_CSR, true);
        }
      }
    }

    // set usedImports on the FileNode
    $node->setAttribute('usedImports', $this->usedImports);
  }
}
