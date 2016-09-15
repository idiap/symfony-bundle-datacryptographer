Data Cryptographer Bundle
=========================

Synopsis
--------

The Data Cryptographer Bundle is a PHP/Symfony bundle which provides a cryptographer
resource/service for common cryptographic operations:
 - data hash (digest/integrity code)
 - key derivation/hash
 - data MAC (authentication code)
 - data en/decipherment (encryption/decryption)

Along matching Doctrine/DBAL data types:
 - hash_string
 - keyhash_string
 - cipher_string/cipher_text
which allow to transparently perform the given cryptographic operations on data being
persisted/retrieved to/from database.
 

Dependencies
------------

 - [MUST] Symfony 2.7 or later
 - [MUST] PHP 5.6 or later
