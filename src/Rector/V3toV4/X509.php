<?php

declare(strict_types=1);

namespace phpseclib\rectorRules\Rector\V3toV4;

use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Name;
use PhpParser\Node\Identifier;
use PhpParser\Node\UseItem;
use PhpParser\Node\Stmt\Use_;
use PhpParser\Node\Stmt\Class_;
use PhpParser\Node\Stmt\Expression;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\ClassConstFetch;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Scalar\String_;
use Rector\PhpParser\Node\FileNode;

use Rector\Rector\AbstractRector;

final class X509 extends AbstractRector
{
  // Collected varnames that refer to phpseclib3\File\X509
  private array $x509Vars = [];
  private array $usedImports = [];
  private bool $isCSR = false;
  private bool $isX509 = false;
  private string $privKeyObj = '';
  private string $pubKeyObj = '';
  private ?string $subjectVar = null;
  private ?string $issuerVar = null;

  // targetClass, targetMethod
  private const METHOD_TO_CLASS = [
    'loadX509'     => ['phpseclib4\File\X509',  'load'],
    'loadCSR'      => ['phpseclib4\File\CSR',   'load'],
    'loadCRL'      => ['phpseclib4\File\CRL',   'load'],
    'loadSPKAC'    => ['phpseclib4\File\SPKAC', 'load'],
    'setPrivateKey'=> ['phpseclib4\File\SPKAC', 'load'],
  ];

  // Methods that identify which phpseclib4 class to import (visitor analysis)
  private const IMPORT_METHOD_MAP = [
    'loadX509'  => 'phpseclib4\File\X509',
    'getDN'     => 'phpseclib4\File\X509',
    'loadCSR'   => 'phpseclib4\File\CSR',
    'loadCRL'   => 'phpseclib4\File\CRL',
    'loadSPKAC' => 'phpseclib4\File\SPKAC',
  ];

  public function getNodeTypes(): array
  {
    return [
      FileNode::class,
      Class_::class,
      MethodCall::class,
      Expression::class,
    ];
  }

  /**
   * Performs the pre-analysis that X509NodeVisitor used to provide as a decorator.
   * Sets attributes on Class_ nodes and populates $this->usedImports.
   * Must run before any Class_/MethodCall refactoring takes place.
   */
  private function analyzeFile(FileNode $node): void
  {
    $this->usedImports = [];
    $finder = new NodeFinder();

    /** @var Class_[] $classes */
    $classes = $finder->findInstanceOf($node->stmts, Class_::class);
    foreach ($classes as $class) {
      $hasCsrMethodCall  = false;
      $hasX509MethodCall = false;
      $hasSetPrivateKey  = false;
      $hasSetPublicKey   = false;
      $privKeyObj        = null;
      $pubKeyObj         = null;
      $issuerVar         = null;
      $subjectVar        = null;

      /** @var MethodCall[] $methodCalls */
      $methodCalls = $finder->findInstanceOf($class->stmts, MethodCall::class);
      foreach ($methodCalls as $methodCall) {
        if (!$methodCall->name instanceof Identifier) {
          continue;
        }
        $methodName = $methodCall->name->toString();
        $varName    = ($methodCall->var instanceof Variable && is_string($methodCall->var->name))
          ? $methodCall->var->name
          : null;

        if ($methodName === 'setPrivateKey') {
          $hasSetPrivateKey = true;
          $arg = $methodCall->args[0]->value ?? null;
          if ($arg instanceof Variable && is_string($arg->name)) {
            $privKeyObj = $arg->name;
          }
          $issuerVar = $varName;
        }

        if ($methodName === 'setPublicKey') {
          $hasSetPublicKey = true;
          $arg = $methodCall->args[0]->value ?? null;
          if ($arg instanceof Variable && is_string($arg->name)) {
            $pubKeyObj = $arg->name;
          }
          $subjectVar = $varName;
        }

        if (in_array($methodName, ['loadCSR', 'signCSR', 'saveCSR'], true)) {
          $hasCsrMethodCall = true;
        }
        if (in_array($methodName, ['setPublicKey', 'saveX509', 'setDN'], true)) {
          $hasX509MethodCall = true;
        }

        if (isset(self::IMPORT_METHOD_MAP[$methodName])) {
          $this->usedImports[self::IMPORT_METHOD_MAP[$methodName]] = true;
        }
      }

      if ($hasCsrMethodCall) {
        $class->setAttribute(X509NodeVisitor::IS_CSR, true);
      }

      if ($hasX509MethodCall) {
        $class->setAttribute(X509NodeVisitor::IS_X509, true);

        $x509Assignments = $finder->find($class->stmts, function (Node $n): bool {
          return $n instanceof Assign
            && $n->expr instanceof New_
            && $n->expr->class instanceof Name
            && in_array($n->expr->class->toString(), ['X509', 'phpseclib3\File\X509'], true);
        });

        if (count($x509Assignments) === 3) {
          $x509Assignments[0]->setAttribute(X509NodeVisitor::IS_FIRST_X509_ASSIGNMENT, true);
        }
      }

      if ($subjectVar !== null) {
        $class->setAttribute(X509NodeVisitor::SUBJECT_VAR, $subjectVar);
      }
      if ($issuerVar !== null) {
        $class->setAttribute(X509NodeVisitor::ISSUER_VAR, $issuerVar);
      }

      if ($hasSetPrivateKey) {
        $class->setAttribute(X509NodeVisitor::PRIV_KEY_OBJ, $privKeyObj);

        if ($class->getAttribute(X509NodeVisitor::IS_CSR, false)) {
          $this->usedImports['phpseclib4\File\CSR'] = true;
        } elseif ($class->getAttribute(X509NodeVisitor::IS_X509, false)) {
          $this->usedImports['phpseclib4\File\X509'] = true;
        } else {
          $this->usedImports['phpseclib4\File\SPKAC'] = true;
        }
      }
      if ($hasSetPublicKey) {
        $class->setAttribute(X509NodeVisitor::PUB_KEY_OBJ, $pubKeyObj);
      }
    }
  }

  private function stmtsWithoutLegacyImport($stmts) {
    return array_values(array_filter($stmts, function ($stmt) {
      if (!$stmt instanceof Use_) {
        return true;
      }

      $stmt->uses = array_values(array_filter($stmt->uses, fn(UseItem $useItem) =>
        !$this->isName($useItem->name, 'phpseclib3\File\X509')
      ));

      // Keep Use_ only if it has at least one UseItem left
      return count($stmt->uses) > 0;
    }));
  }

  private function getAssignedMethodCall(Expression $node): ?MethodCall {
    if (
      $node->expr instanceof Assign &&
      $node->expr->expr instanceof MethodCall
    ) {
      return $node->expr->expr;
    }
    return null;
  }

  private function wrapPrivateKeyArg(array $args): array
  {
    if (isset($args[0])) {
      $args[0]->value = new MethodCall($args[0]->value, new Identifier('getPublicKey'));
    }
    return $args;
  }

  private function reset() {
    $this->isCSR = false;
    $this->isX509 = false;
    $this->subjectVar = null;
    $this->issuerVar = null;
    $this->privKeyObj = '';
    $this->pubKeyObj = '';
  }

  public function refactor(Node $node): int|null|Node
  {
    if($node instanceof FileNode) {
      // Perform the pre-analysis (previously done by X509NodeVisitor) to avoid
      // depending on the decorator mechanism, which has singleton-lifetime issues
      // in combined PHPUnit runs.
      $this->analyzeFile($node);

      // Remove old import
      $node->stmts = $this->stmtsWithoutLegacyImport($node->stmts);

      $newImportNodes = [];
      foreach(array_keys($this->usedImports) as $className) {
        $newImportNodes[] = new Use_([new UseItem(new Name($className))]);
      }
      $node->stmts = array_merge($newImportNodes, $node->stmts);
      return $node;
    }

    if($node instanceof Class_) {
      // A file can have several classes, so reset for the new class
      $this->reset();

      if ($node->getAttribute(X509NodeVisitor::IS_X509, false)) {
        $this->isX509 = true;
        $this->pubKeyObj = $node->getAttribute(X509NodeVisitor::PUB_KEY_OBJ, '');

        $this->issuerVar = $node->getAttribute(X509NodeVisitor::ISSUER_VAR);
        $this->subjectVar = $node->getAttribute(X509NodeVisitor::SUBJECT_VAR);
      }

      if ($node->getAttribute(X509NodeVisitor::IS_CSR, false)) {
        $this->isCSR = true;
        $this->x509Vars['csr'] = true;
      }

      $this->privKeyObj = $node->getAttribute(X509NodeVisitor::PRIV_KEY_OBJ, '');
      return null;
    }

    // Collect varnames that refer to phpseclib3\File\X509
    // And delete instance
    if ($node instanceof Expression
      && $node->expr instanceof Assign
      && $node->expr->expr instanceof New_
    ) {
      if ($this->isNames($node->expr->expr->class, ['X509', 'phpseclib3\File\X509'])) {
        $varName = $this->getName($node->expr->var);
        if ($varName !== null) {
          $this->x509Vars[$varName] = true;
        }

        if ($this->isX509 && $node->expr->getAttribute(X509NodeVisitor::IS_FIRST_X509_ASSIGNMENT, false)) {
          return new Expression(
            new Assign(
              new Variable('x509'),
              new New_(
                new Name('X509'),
                [new Arg(new Variable($this->pubKeyObj))]
              )
            )
          );
        }

        return NodeTraverser::REMOVE_NODE;
      }
      return null;
    }

    // Delete validateDate()
    // This is handled by validateSignature() now
    if ($node instanceof Expression) {
      $call = $this->getAssignedMethodCall($node) ?? ($node->expr instanceof MethodCall ? $node->expr : null);

      if (
        $call instanceof MethodCall &&
        $call->var instanceof Variable &&
        isset($this->x509Vars[$this->getName($call->var)]) &&
        $this->isName($call->name, 'validateDate')
      ) {
        return NodeTraverser::REMOVE_NODE;
      }
    }

    if ($node instanceof Expression) {
      $call = $this->getAssignedMethodCall($node);

      if (
        $call instanceof MethodCall &&
        $call->var instanceof Variable &&
        isset($this->x509Vars[$this->getName($call->var)]) &&
        $this->isNames($call->name, ['signCSR', 'signSPKAC'])
      ) {
        return new Expression(
          new MethodCall(
            new Variable($this->privKeyObj),
            'sign',
            [new Arg($node->expr->var)]
          )
        );
      }
    }

    if($this->isX509 && $node instanceof Expression) {
      // Remove setPublicKey() and setPrivateKey() for X509
      if ($node->expr instanceof MethodCall) {
        $methodCall = $node->expr;
        if (!$methodCall->var instanceof Variable) {
          return null;
        }
        if($this->isNames($methodCall->name, ['setPublicKey', 'setPrivateKey'])) {
          return NodeTraverser::REMOVE_NODE;
        }
      }

      // $result = $x509->sign($issuer, $subject) to $privKey->sign($x509)
      $call = $this->getAssignedMethodCall($node);
      if (
          $call instanceof MethodCall &&
          $call->var instanceof Variable &&
          isset($this->x509Vars[$this->getName($call->var)]) &&
          $this->isName($call->name, 'sign')
      ) {
        return new Expression(
          new MethodCall(
            new Variable($this->privKeyObj),
            'sign',
            [new Arg($call->var)]
          )
        );
      }
    }

    if (!$node instanceof MethodCall || !$node->var instanceof Variable) {
      return null;
    }

    // Refactor method calls on collected vars
    // varName = x509
    $varName = $this->getName($node->var);
    if ($varName === null || ! isset($this->x509Vars[$varName])) {
      return null;
    }

    $methodName = $this->getName($node->name);
    if ($methodName === null) {
      return null;
    }

    if (isset(self::METHOD_TO_CLASS[$methodName])) {
      [$targetClass, $targetMethod] = self::METHOD_TO_CLASS[$methodName];
      $parts = explode('\\', $targetClass);
      $shortClass = end($parts);

      if ($methodName === 'setPrivateKey') {
        $args = $this->wrapPrivateKeyArg($node->args);

        if ($this->isCSR) {
          return new Assign(
            new Variable('csr'),
            new New_(new Name('CSR'), $args)
          );
        }

        return new Assign(
          new Variable('spkac'),
          new New_(new Name($shortClass), $args)
        );
      }

      return new StaticCall(new Name($shortClass), $targetMethod, $node->args);
    }

    switch ($methodName) {
      case 'setDN':
        if (!$this->isX509) {
          return null;
        }
        $node->var = new Variable('x509');
        // remove leading slash
        if (!empty($node->args[0])) {
          $arg = $node->args[0]->value;
          if ($arg instanceof String_) {
            $arg->value = ltrim($arg->value, '/');
          }
        }
        if ($varName === $this->subjectVar) {
          $node->name = new Identifier('setSubjectDN');
        }
        if ($varName === $this->issuerVar) {
          $node->name = new Identifier('setIssuerDN');
        }
        return $node;

      case 'getDN':
        $node->name = new Identifier('getSubjectDN');
        // Add X509::DN_ARRAY only if no argument present
        if (count($node->args) === 0) {
          $node->args[0] = new Arg(
            new ClassConstFetch(
              new Name('X509'),
              'DN_ARRAY'
            )
          );
        }
        return $node;

      case 'setDNProp':
        $node->name = new Identifier('addDNProp');
        if($this->isCSR) {
          $node->var = new Variable('csr');
        }
        return $node;

      case 'saveCSR':
        return new Methodcall($node->args[0]->value, new Identifier('toString'));

      case 'saveX509':
        return new Methodcall($node->var, new Identifier('toString'));

      case 'setChallenge':
        $node->var = new Variable('spkac');
        return $node;

      default:
        return null;
    }
  }
}
