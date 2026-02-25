<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use Rector\Rector\AbstractRector;

use PhpParser\Node;
use PhpParser\Node\Name;
use PhpParser\Node\Identifier;
use PhpParser\Node\UseItem;
use PhpParser\Node\Stmt\Use_;
use PhpParser\Node\Stmt\UseUse;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use Rector\PhpParser\Node\FileNode;

use Rector\NodeTypeResolver\Node\AttributeKey;

final class HandleFileX509Imports extends AbstractRector
{
  // Collected varnames that refer to phpseclib3\File\X509
  private array $x509Vars = [];
  private array $usedImports = [];
  private bool $isCSR = false;

  const METHOD_TO_CLASS = [
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
      FileNode::class,
      Class_::class,
      Use_::class,
      MethodCall::class,
      Expression::class,
    ];
  }

  public function refactor(Node $node): int|null|Node|array
  {
    if($node instanceof FileNode) {
      $this->usedImports = $node->getAttribute('usedImports', []);
      return null;
    }

    if($node instanceof Class_) {
      // A file can have several classes, so reset for the new class
      $this->isCSR = false;

      if ($node->getAttribute(X509NodeVisitor::IS_CSR, false)) {
        $this->isCSR = true;
      }
      return null;
    }

    // Remove old import and add the new ones.
    if ($node instanceof Use_) {
      // remove old import
      $node->uses = array_values(array_filter(
        $node->uses,
        fn($useUse) => ! $this->isName($useUse->name, 'phpseclib3\File\X509')
      ));

      // add new imports
      if (count($node->uses) === 0) {
        foreach (array_keys($this->usedImports) as $className) {
          // Skip if already imported? You can check existing use statements here if needed
          $node->uses[] = new UseItem(new Name($className));
        }
      }
      return $node;
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

    if (!$node instanceof MethodCall) {
      return null;
    }

    if (!$node->var instanceof Variable) {
      return null;
    }

    // Refactor method calls on collected vars
    // varName = x509
    $varName = $this->getName($node->var);
    if ($varName === null || ! isset($this->x509Vars[$varName])) {
      return null;
    }

    $methodName = $this->getName($node->name);

    if ($methodName === null || ! isset(self::METHOD_TO_CLASS[$methodName])) {
      return null;
    }

    [$targetClass, $targetMethod] = self::METHOD_TO_CLASS[$methodName];

    $parts = explode('\\', $targetClass);
    $shortClass = end($parts);

    // add ->getPublicKey() to args for setPrivateKey
    $args = $node->args;
    if ($methodName === 'setPrivateKey' && isset($args[0])) {
      $wrappedExpr = new MethodCall(
          $args[0]->value,
          new Identifier('getPublicKey')
      );
      $args[0]->value = $wrappedExpr;
    }

    $staticCall = new StaticCall(
      new Name($shortClass),
      $targetMethod,
      $args
    );

    if ($methodName === 'setPrivateKey') {
      // $csr = new CSR($privKey->getPublicKey());
      if($this->isCSR) {
        return new Assign(
          new Variable('csr'),
          new New_(
            new Name('CSR'),
            $args
          )
        );
      }
      // $spkac = CRL::loadCRL(file_get_contents('spkac.txt'));
      return new Assign(
        new Variable('spkac'),
        $staticCall
      );
    }
    return $staticCall;
  }
}