# Rules for v3 to v4 Rector

The Rector Set for the phpseclib `v3` to phpseclib `v4` upgrade includes
a [Node Visitor](https://getrector.com/documentation/creating-node-visitor) and one custom rule, called X509.
It migrates code that uses `phpseclib3\File\X509` to the newer `phpseclib4\File` API.
## X509 Node Visitor

With a NodeVisitor, nodes can be decorated with attributes before being used by one or more rules.

In `v3` there is only `phpseclib3\File\X509` for all available certs. `v4` seperates them to
`phpseclib4\File\X509`, `phpseclib4\File\CSR` and `phpseclib4\File\CRL`.

X509NodeVisitor is used in the X509 rule to analyze phpseclib X.509-related method calls and determine which phpseclib4 classes should be imported.

Additionally it collects other information, that are required for the refactor:
Like the information, if it is `CSR` import to handle the static calls correctly and adapt the variable names.
Also the parameter, passed to `setPrivateKey()`, since this is needed to refactor `$x509->signCSR()` to `$privKey->sign($csr)`.


## X.509

In phpseclib v4, X.509-related functionality has been split into dedicated classes such as `X509`, `CSR`, and `CRL`,
and several methods have been renamed or redesigned.

The rule performs the following transformations:

- Updates imports by removing `phpseclib3\File\X509` and adding the required phpseclib4 classes.
- Removes instantiations of `phpseclib3\File\X509` and tracks variables that previously referenced it.
- Converts instance method calls into the corresponding static calls on the appropriate phpseclib4 class.
- Migrates calls such as:
    - `loadX509()` → `X509::load()`
    - `loadCSR()` → `CSR::loadCSR()`
    - `loadCRL()` → `CRL::loadCRL()`
- Rewrites API changes:
    - `getDN()` → `getSubjectDN(X509::DN_ARRAY)`
    - `setDNProp()` → `addDNProp()`
    - `saveCSR()` → `$csr->toString()`
- Removes obsolete call `validateDate()`, which is now handled internally by `validateSignature()`

A detailled overview of the changes is given by the following chapter.

## V3 to V4 differences
### X.509
#### Read cert

```php
$x509 = new \phpseclib3\File\X509();
$cert = $x509->loadX509(file_get_contents('google.crt'));
```
will be refactored to
```php
$cert = \phpseclib4\File\X509::load(file_get_contents('google.crt'));
```

#### Get Subject DN

```php
$x509->getDN(...);
$x509a->getDN();
```
will be refactored to
```php
$x509->getSubjectDN(...);
$x509a->getSubjectDN(X509::DN_ARRAY);
```

#### Create cert

Previously you needed three X509 instances - now you just need one.
<!-- If this is too difficult to do we can skip it and just make note of it in the README.md under some sort of Limitations section -->

```php
$subject = new X509();
$subject->setPublicKey($pubKey); // $pubKey is a PublicKey objet
$subject->setDN('/O=phpseclib demo subject');

$issuer = new X509();
$issuer->setPrivateKey($privKey); // $privKey is a PrivateKey object
$issuer->setDN('/O=phpseclib demo issuer');

$x509 = new X509();
$result = $x509->sign($issuer, $subject);
echo $x509->saveX509($result);
```
will be refactored to
```php
$x509 = new X509($pubKey);
$x509->setSubjectDN('O=phpseclib demo issuer');
$x509->setIssuerDN('O=phpseclib demo subject');
$privKey->sign($x509);
echo $x509->toString();
```

#### Set DN Prop

`setDNProp()` in phpseclib v3 really was adding a DN prop even if one already existed.

```php
$x509->setDNProp('id-at-organizationName', 'phpseclib CA cert');
```
will be refactored to
```php
$x509->addDNProp('id-at-organizationName', 'phpseclib CA cert');
```

### CSR

#### Read cert

```php
$x509 = new X509();
$csr = $x509->loadCSR(file_get_contents('csr.csr'));
```
will be refactored to
```php
$csr = \phpseclib4\File\CSR::loadCSR(file_get_contents('csr.csr'));
```

#### Set DN Prop

`setDNProp()` in phpseclib v3 really was adding a DN prop even if one already existed.
This is same as the `setDNProp` in the X509 section above.

```php
$x509->setDNProp('id-at-organizationName', 'phpseclib CA cert');
```
will be refactored to
```php
$x509->addDNProp('id-at-organizationName', 'phpseclib CA cert');
```

#### Create cert TBD

Previously you needed three X509 instances - now you just need one. If this is too difficult to do we can skip it and just make note of it in the README.md under some sort of Limitations section

```php
$x509 = new X509();
$x509->setPrivateKey($privKey);
$x509->setDNProp('id-at-organizationName', 'phpseclib demo cert');

$csr = $x509->signCSR();
echo $x509->saveCSR($csr);
```
will be refactored to
```php
$csr = new \phpseclib4\File\CSR($privKey->getPublicKey());
$csr->setDNProp('id-at-organizationName', 'phpseclib demo cert');

$privKey->sign($csr);
echo $csr->toString();
```

### CRL

#### Read cert

```php
$x509 = new X509();
$crl = $x509->loadCRL(file_get_contents('crl.bin'));
```
will be refactored to
```php
$crl = \phpseclib4\File\CRL::loadCRL(file_get_contents('crl.bin'));
```

### SPKAC

#### Read cert

```php
$x509 = new X509();
$spkac = $x509->loadSPKAC(file_get_contents('spkac.txt'));
```
will be refactored to
```php
$spkac = \phpseclib4\File\CRL::loadCRL(file_get_contents('spkac.txt'));
```

#### Read cert

```php
$x509 = new X509();
$x509->setPrivateKey($privKey);
$x509->setChallenge('123456789');
$spkac = $x509->signSPKAC();
```
will be refactored to
```php
$spkac = \phpseclib4\File\CRL::loadCRL($privKey->getPublicKey());
$spkac->setChallenge('123456789');
$privKey->sign($spkac);
```
