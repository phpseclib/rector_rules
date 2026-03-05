# Rules for v3 to v4 Rector

The Rector Set for the phpseclib `v3` to phpseclib `v4` upgrade includes
a [Node Visitor](https://getrector.com/documentation/creating-node-visitor) and one custom rule, called X509.

## X509 Node Visitor

With a NodeVisitor, nodes can be decorated with attributes before being used by one or more rules.

In `v3` there is only `phpseclib3\File\X509` for all available certs. `v4` seperates them to
`phpseclib4\File\X509`, `phpseclib4\File\CSR` and `phpseclib4\File\CRL`.

X509NodeVisitor is used in the X509 rule to analyze phpseclib X.509-related method calls and determine which phpseclib4 classes should be imported.


## X.509

### Static calls

In `v4` parsing is moved to static call and there is no need to instantiate the object.

It removes the `$x509 = new X509()` assignments.

Additionally, it removes the Date Validation `$x509->validateDate()`.
In `v4` `validateSignature()` takes care of this, although one could write their own custom date validation code.


### Set DN Prop

`setDNProp()` in phpseclib `v3` was adding a DN prop even if one already existed. In `v4` `addDNProp` is used instead.

It replaces
```php
$x509->setDNProp('id-at-organizationName', 'phpseclib CA cert');
```
with

```php
$x509->addDNProp('id-at-organizationName', 'phpseclib CA cert');
```

### Get Subject DN

In v4 `getDN` is no longer used and instead `getSubjectDN` is used. If no parameter is present in v3 then X509::DN_ARRAY should be present in v4

It replaces
```php
$x509->getDN(...);
```
with

```php
$x509->getSubjectDN(...);
```
