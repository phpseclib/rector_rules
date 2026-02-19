<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use Rector\Rector\AbstractRector;

use PhpParser\BuilderFactory;
use PhpParser\NodeTraverser;
use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Name\FullyQualified;
use PhpParser\Node\Identifier;

use PhpParser\Node\Stmt\Nop;
use PhpParser\Node\Stmt\Use_;
use PhpParser\Node\Stmt\UseUse;
use PhpParser\Node\Stmt\Expression;

use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;

final class HandleFileX509Imports extends AbstractRector
{
  // Collected varnames that refer to phpseclib3\File\X509
  private array $x509Vars = [];
  private array $usedImports = [];
  private bool $isCSR = false;

  private const METHOD_TO_CLASS = [
    'loadX509' => ['phpseclib4\File\X509', 'load'],
    'loadCSR'  => ['phpseclib4\File\CSR', 'loadCSR'],
    'loadCRL'  => ['phpseclib4\File\CRL', 'loadCRL'],
    'loadSPKAC'=> ['phpseclib4\File\CRL', 'loadCRL'],
    'setPrivateKey'=> ['phpseclib4\File\CRL', 'loadCRL'], // Set to CRL per default
    // 'setPrivateKey'=> ['phpseclib4\File\CSR', 'new CSR($privKey->getPublicKey())'],
  ];

  public function getNodeTypes(): array
  {
    return [
      Use_::class,
      MethodCall::class,
      Expression::class,
    ];
  }

  public function refactor(Node $node): int|null|Node
  {
    // Remove import for now. We will add the correct one later
    if ($node instanceof Use_) {
      // filter out any UseUse that matches the old class
      $node->uses = array_values(array_filter(
        $node->uses,
        fn($useUse) => ! $this->isName($useUse->name, 'phpseclib3\File\X509')
      ));

      // if no UseUse left, remove the entire Use_ node
      if (count($node->uses) === 0) {
        return NodeTraverser::REMOVE_NODE;
      }
    }

    // Collect varnames that refer to phpseclib3\File\X509
    if ($node instanceof Expression && $node->expr instanceof Assign && $node->expr->expr instanceof New_) {
      if ($this->isNames($node->expr->expr->class, ['X509', 'phpseclib3\File\X509'])) {
        $varName = $this->getName($node->expr->var);
        if ($varName !== null) {
          $this->x509Vars[$varName] = true;
        }
      }
      return null;
    }

    // Refactor method calls on collected vars
    if ($node instanceof MethodCall && $node->var instanceof Variable) {
      $varName = $this->getName($node->var);
      if ($varName === null || ! isset($this->x509Vars[$varName])) {
        return null;
      }

      $methodName = $this->getName($node->name);

      // check for setPrivateKey
      // setChallenge() or signSPKAC() is a CRL import
      if(in_array($methodName, ['setDnProp', 'signCSR','saveCSR'])) {
        $this->isCSR = true;
      }
      if ($methodName === null || ! isset(self::METHOD_TO_CLASS[$methodName])) {
        return null;
      }

      [$targetClass, $targetMethod] = self::METHOD_TO_CLASS[$methodName];

      $this->usedImports[(string) $targetClass] = true;

      $parts = explode('\\', $targetClass);
      $shortClass = end($parts);

      // add ->getPublicKey() to args for setPrivateKey
      $args = $node->args;
      if ($methodName === 'setPrivateKey' && isset($args[0])) {
        $originalExpr = $args[0]->value;

        $wrappedExpr = new MethodCall(
            $originalExpr,
            new Identifier('getPublicKey')
        );

        $args[0]->value = $wrappedExpr;
      }

      return new StaticCall(
        new Name($shortClass),
        $targetMethod,
        $args
      );
    }

    return null;
  }


  public function afterTraverse(array $nodes): ?array
  {
    if(!$this->usedImports) {
      return null;
    }
    $useNodes = [];

    // Add only valid imports
    foreach ($this->usedImports as $className => $_) {
      $useNode = new Use_([
        new UseUse(new Name($className))
      ]);

      $useNodes[] = $useNode;
      $useNodes[] = new Nop();
    }

    $this->usedImports = [];
    array_splice($nodes, 0, 0, $useNodes);
    return $nodes;
  }
}