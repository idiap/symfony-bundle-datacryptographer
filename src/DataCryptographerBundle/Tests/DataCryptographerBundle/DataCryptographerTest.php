<?php // -*- mode:php; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
// [PHPUnit\tests\]DataCryptographerBundle\DataCryptographerTest.php

/** Data Cryptographer Bundle
 *
 * <P><B>COPYRIGHT:</B></P>
 * <PRE>
 * Data Cryptographer Bundle
 * Copyright (C) 2016 Idiap Research Institute <http://www.idiap.ch>
 * Author: Cedric Dufour <http://cedric.dufour.name>
 *
 * This file is part of the Data Cryptographer Bundle.
 *
 * The Data Cryptographer Bundle is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, Version 3.
 *
 * The Data Cryptographer Bundle is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * </PRE>
 *
 * @package    DataCryptographerBundle
 * @subpackage PHPUnit
 * @copyright  2016 Idiap Research Institute <http://www.idiap.ch>
 * @author     Cedric Dufour <http://cedric.dufour.name>
 * @license    http://www.gnu.org/licenses/gpl-3.0.html GNU General Public License (GPL) Version 3
 * @version    %{VERSION}
 * @link       https://github.com/idiap/symfony-bundle-datacryptographer
 */

namespace Tests\DataCryptographerBundle;
use DataCryptographerBundle\DataCryptographer;

/** Data cryptographer test class
 *
 * @package    DataCryptographerBundle
 * @subpackage PHPUnit
 */
class DataCryptographerTest
  extends \PHPUnit_Framework_TestCase
{

  /*
   * CONSTANTS
   ********************************************************************************/

  const DEFAULT_PASSWORD = 'UDm9onE55UpS/OteDVirXYpY1cbmIPzv';
  const DEFAULT_PASSWORD_ALGORITHM = 'P2SHA256';
  const DEFAULT_PASSWORD_ITERATIONS = 1;
  const DEFAULT_HASH_ALGORITHM = 'HSHA256';
  const DEFAULT_KEY_ALGORITHM = 'P2SHA256';
  const DEFAULT_KEY_ITERATIONS = 10;
  const DEFAULT_KEY_SALT = 'bIOWrpirNezjDHbUDyFNAnxsq0nF/c/c';
  const DEFAULT_MAC_ALGORITHM = 'HSHA256';
  const DEFAULT_MAC_SALT = 'GdBio9ICYXAg.C7ko4obigNReKyZbsLr';
  const DEFAULT_CIPHER_ALGORITHM = 'AES256';
  const DEFAULT_CIPHER_SALT = 'tkyLMfmLsFiGzRvI5VG7c4alfBiaCT3u';
  const DEFAULT_DATA = 'The quick brown fox jumps over the lazy dog';


  /*
   * METHODS
   ********************************************************************************/

  public function testHash() {

    // Loop through supported hash/encoding algorithms
    foreach (DataCryptographer::HASH_ALGORITHMS as $sHashAlgorithm => $aHashAlgorithm) {
      foreach (DataCryptographer::ENCODING_ALGORITHMS as $sEncodingAlgorithm => $aEncodingAlgorithm) {
        $sHeader = sprintf('{%s:%s}', $sHashAlgorithm, $sEncodingAlgorithm);
        print("\nHASH".$sHeader);

        // Instantiate cryptographer (NB: ignore warnings about NULL algorithms)
        $oDataCryptographer = @new DataCryptographer(
          self::DEFAULT_PASSWORD,
          self::DEFAULT_PASSWORD_ALGORITHM,
          self::DEFAULT_PASSWORD_ITERATIONS,
          $sHashAlgorithm,
          '-',
          self::DEFAULT_KEY_ITERATIONS,
          '-',
          self::DEFAULT_MAC_SALT,
          '-',
          self::DEFAULT_CIPHER_SALT,
          false
        );
        try {
          $oDataCryptographer->changeEncoding($sEncodingAlgorithm);
        } catch(\Exception $e) {
          $this->assertStringEndsWith('[NO_ENCODING_ALGORITHM]', $e->getMessage());
          continue;
        }

        // Crypto operation (raw)
        $aHash = $oDataCryptographer->hash(self::DEFAULT_DATA, true);
        $this->assertArrayHasKey('hash', $aHash);
        $this->assertArrayHasKey('salt', $aHash);

        // ... payload (see ASCII operation below)

        // ... reverse (same cryptographer)
        $this->assertTrue($oDataCryptographer->hashVerify(self::DEFAULT_DATA, $aHash, true));
        $this->assertTrue($oDataCryptographer->hashVerify(self::DEFAULT_DATA, $aHash, false));
        $this->assertFalse($oDataCryptographer->hashVerify(strrev(self::DEFAULT_DATA), $aHash, true));
        $this->assertFalse($oDataCryptographer->hashVerify(strrev(self::DEFAULT_DATA), $aHash, false));

        // Crypto operation (ASCII)
        $sHash = $oDataCryptographer->hash(self::DEFAULT_DATA, false);
        $this->assertStringStartsWith($sHeader, $sHash);
        $sPayload = substr($sHash, strlen($sHeader));

        // ... binary
        $aBinary = $oDataCryptographer->hashAscii2Binary($sHash);
        $this->assertArrayHasKey('header', $aBinary);
        $this->assertArrayHasKey('payload', $aBinary);

        // ... header
        $aHeader = $aBinary['header'];
        $this->assertArrayHasKey('hash', $aHeader);
        $this->assertEquals($sHashAlgorithm, $aHeader['hash']);

        // ... payload
        $aPayload = $aBinary['payload'];
        $this->assertArrayHasKey('hash', $aPayload);
        $this->assertArrayHasKey('salt', $aPayload);
        switch (substr($sHeader, -5)) {
        case ':B64}':
          $this->assertEquals(base64_decode($sPayload), $aPayload['hash'].$aPayload['salt']);
          break;
        case ':HEX}':
          $this->assertEquals(hex2bin($sPayload), $aPayload['hash'].$aPayload['salt']);
          break;
        default:
          $this->assertEquals($sPayload, $aPayload['hash'].$aPayload['salt']);
          break;
        }
        switch ($sHashAlgorithm) {
        case '-':
          $this->assertEquals(self::DEFAULT_DATA, $aPayload['hash']);
          break;
        case 'MD5':
        case 'SHA1':
        case 'SHA224':
        case 'SHA256':
        case 'SHA384':
        case 'SHA512':
          $this->assertEquals(hash($aHashAlgorithm[0], self::DEFAULT_DATA, true), $aPayload['hash']);
          break;
        case 'HMD5':
        case 'HSHA1':
        case 'HSHA224':
        case 'HSHA256':
        case 'HSHA384':
        case 'HSHA512':
          $this->assertEquals(hash_hmac($aHashAlgorithm[0], self::DEFAULT_DATA, $aPayload['salt'], true), $aPayload['hash']);
          break;
        default:
          $this->assertEquals($sHashAlgorithm, 'Unknown algorithm');
          break;
        }

        // ... reverse (same cryptographer)
        $this->assertTrue($oDataCryptographer->hashVerify(self::DEFAULT_DATA, $sHash, true));
        $this->assertTrue($oDataCryptographer->hashVerify(self::DEFAULT_DATA, $sHash, false));
        $this->assertFalse($oDataCryptographer->hashVerify(strrev(self::DEFAULT_DATA), $sHash, true));
        $this->assertFalse($oDataCryptographer->hashVerify(strrev(self::DEFAULT_DATA), $sHash, false));


        // ... reverse (new generic cryptographer)
        $oDataCryptographer = @new DataCryptographer(
          self::DEFAULT_PASSWORD,
          self::DEFAULT_PASSWORD_ALGORITHM,
          self::DEFAULT_PASSWORD_ITERATIONS,
          self::DEFAULT_HASH_ALGORITHM,
          self::DEFAULT_KEY_ALGORITHM,
          self::DEFAULT_KEY_ITERATIONS,
          self::DEFAULT_MAC_ALGORITHM,
          self::DEFAULT_MAC_SALT,
          self::DEFAULT_CIPHER_ALGORITHM,
          self::DEFAULT_CIPHER_SALT,
          false
        );
        $this->assertTrue($oDataCryptographer->hashVerify(self::DEFAULT_DATA, $sHash, true));
        $this->assertTrue($oDataCryptographer->hashVerify(self::DEFAULT_DATA, $sHash, false));
        $this->assertFalse($oDataCryptographer->hashVerify(strrev(self::DEFAULT_DATA), $sHash, true));
        $this->assertFalse($oDataCryptographer->hashVerify(strrev(self::DEFAULT_DATA), $sHash, false));

      }
    }

  }

  public function testKey() {

    // Loop through supported key/salt/encoding algorithms
    foreach (DataCryptographer::KEY_ALGORITHMS as $sKeyAlgorithm => $aKeyAlgorithm) {
      foreach (array(null, self::DEFAULT_KEY_SALT) as $sSalt) {
        foreach (DataCryptographer::ENCODING_ALGORITHMS as $sEncodingAlgorithm => $aEncodingAlgorithm) {
          $sHeader = sprintf('{%s:%d:%s}', $sKeyAlgorithm, self::DEFAULT_KEY_ITERATIONS, $sEncodingAlgorithm);
          print("\nKEY".$sHeader);

          // Instantiate cryptographer (NB: ignore warnings about NULL algorithms)
          $oDataCryptographer = @new DataCryptographer(
            self::DEFAULT_PASSWORD,
            self::DEFAULT_PASSWORD_ALGORITHM,
            self::DEFAULT_PASSWORD_ITERATIONS,
            '-',
            $sKeyAlgorithm,
            self::DEFAULT_KEY_ITERATIONS,
            '-',
            self::DEFAULT_MAC_SALT,
            '-',
            self::DEFAULT_CIPHER_SALT,
            false
          );
          try {
            $oDataCryptographer->changeEncoding($sEncodingAlgorithm);
          } catch(\Exception $e) {
            $this->assertStringEndsWith('[NO_ENCODING_ALGORITHM]', $e->getMessage());
            continue;
          }

          // Crypto operation (raw)
          $aKey = $oDataCryptographer->key(self::DEFAULT_DATA, $sSalt, true);
          $this->assertArrayHasKey('key', $aKey);
          $this->assertArrayHasKey('salt', $aKey);

          // ... payload (see ASCII operation below)

          // ... reverse (same cryptographer)
          $this->assertTrue($oDataCryptographer->keyVerify(self::DEFAULT_DATA, $aKey, $sSalt, true));
          $this->assertTrue($oDataCryptographer->keyVerify(self::DEFAULT_DATA, $aKey, $sSalt, false));
          $this->assertFalse($oDataCryptographer->keyVerify(strrev(self::DEFAULT_DATA), $aKey, $sSalt, true));
          $this->assertFalse($oDataCryptographer->keyVerify(strrev(self::DEFAULT_DATA), $aKey, $sSalt, false));

          // Crypto operation (ASCII)
          $sKey = $oDataCryptographer->key(self::DEFAULT_DATA, $sSalt, false);
          $this->assertStringStartsWith($sHeader, $sKey);
          $sPayload = substr($sKey, strlen($sHeader));

          // ... binary
          $aBinary = $oDataCryptographer->keyAscii2Binary($sKey, $sSalt);
          $this->assertArrayHasKey('header', $aBinary);
          $this->assertArrayHasKey('payload', $aBinary);

          // ... header
          $aHeader = $aBinary['header'];
          $this->assertArrayHasKey('key', $aHeader);
          $this->assertArrayHasKey('iterations', $aHeader);
          $this->assertEquals($sKeyAlgorithm, $aHeader['key']);
          $this->assertEquals(self::DEFAULT_KEY_ITERATIONS, $aHeader['iterations']);

          // ... payload
          $aPayload = $aBinary['payload'];
          $this->assertArrayHasKey('key', $aPayload);
          $this->assertArrayHasKey('salt', $aPayload);
          switch (substr($sHeader, -5)) {
          case ':B64}':
            $this->assertEquals(base64_decode($sPayload), is_null($sSalt) ? $aPayload['key'].$aPayload['salt'] : $aPayload['key']);
            break;
          case ':HEX}':
            $this->assertEquals(hex2bin($sPayload), is_null($sSalt) ? $aPayload['key'].$aPayload['salt'] : $aPayload['key']);
            break;
          default:
            $this->assertEquals($sPayload, is_null($sSalt) ? $aPayload['key'].$aPayload['salt'] : $aPayload['key']);
            break;
          }
          switch ($sKeyAlgorithm) {
          case '-':
            $this->assertEquals(self::DEFAULT_DATA, $aPayload['key']);
            break;
          case 'P2MD5':
          case 'P2SHA1':
          case 'P2SHA224':
          case 'P2SHA256':
          case 'P2SHA384':
          case 'P2SHA512':
            $this->assertEquals(hash_pbkdf2($aKeyAlgorithm[1], self::DEFAULT_DATA, $aPayload['salt'], self::DEFAULT_KEY_ITERATIONS, 0, true), $aPayload['key']);
            break;
          default:
            $this->assertEquals($sKeyAlgorithm, 'Unknown algorithm');
            break;
          }

          // ... reverse (same cryptographer)
          $this->assertTrue($oDataCryptographer->keyVerify(self::DEFAULT_DATA, $sKey, $sSalt, true));
          $this->assertTrue($oDataCryptographer->keyVerify(self::DEFAULT_DATA, $sKey, $sSalt, false));
          $this->assertFalse($oDataCryptographer->keyVerify(strrev(self::DEFAULT_DATA), $sKey, $sSalt, true));
          $this->assertFalse($oDataCryptographer->keyVerify(strrev(self::DEFAULT_DATA), $sKey, $sSalt, false));


          // ... reverse (new generic cryptographer)
          $oDataCryptographer = @new DataCryptographer(
            self::DEFAULT_PASSWORD,
            self::DEFAULT_PASSWORD_ALGORITHM,
            self::DEFAULT_PASSWORD_ITERATIONS,
            self::DEFAULT_HASH_ALGORITHM,
            self::DEFAULT_KEY_ALGORITHM,
            self::DEFAULT_KEY_ITERATIONS,
            self::DEFAULT_MAC_ALGORITHM,
            self::DEFAULT_MAC_SALT,
            self::DEFAULT_CIPHER_ALGORITHM,
            self::DEFAULT_CIPHER_SALT,
            false
          );
          $this->assertTrue($oDataCryptographer->keyVerify(self::DEFAULT_DATA, $sKey, $sSalt, true));
          $this->assertTrue($oDataCryptographer->keyVerify(self::DEFAULT_DATA, $sKey, $sSalt, false));
          $this->assertFalse($oDataCryptographer->keyVerify(strrev(self::DEFAULT_DATA), $sKey, $sSalt, true));
          $this->assertFalse($oDataCryptographer->keyVerify(strrev(self::DEFAULT_DATA), $sKey, $sSalt, false));

        }
      }
    }

  }

  public function testMac() {

    // Loop through supported (internal)key/MAC/encoding algorithms
    foreach (DataCryptographer::KEY_ALGORITHMS as $sPasswordAlgorithm => $aPasswordAlgorithm) {
      foreach (DataCryptographer::MAC_ALGORITHMS as $sMacAlgorithm => $aMacAlgorithm) {
        switch ($aPasswordAlgorithm[0]) {
        case null:
          $sMacKey = self::DEFAULT_PASSWORD;
          break;
        case 'PBKDF2':
          $sMacKey = hash_pbkdf2($aPasswordAlgorithm[1], self::DEFAULT_PASSWORD, self::DEFAULT_MAC_SALT, self::DEFAULT_PASSWORD_ITERATIONS, DataCryptographer::KEY_SIZE_INTERNAL, true);
          break;
        }
        $sMacKey = substr($sMacKey, 0, $aMacAlgorithm[3]);
        foreach (DataCryptographer::ENCODING_ALGORITHMS as $sEncodingAlgorithm => $aEncodingAlgorithm) {
          $sHeader = sprintf('{%s:%s}', $sMacAlgorithm, $sEncodingAlgorithm);
          print("\nMAC".$sHeader);

          // Instantiate cryptographer (NB: ignore warnings about NULL algorithms)
          $oDataCryptographer = @new DataCryptographer(
            self::DEFAULT_PASSWORD,
            $sPasswordAlgorithm,
            self::DEFAULT_PASSWORD_ITERATIONS,
            '-',
            '-',
            self::DEFAULT_KEY_ITERATIONS,
            $sMacAlgorithm,
            self::DEFAULT_MAC_SALT,
            '-',
            self::DEFAULT_CIPHER_SALT,
            false
          );
          try {
            $oDataCryptographer->changeEncoding($sEncodingAlgorithm);
          } catch(\Exception $e) {
            $this->assertStringEndsWith('[NO_ENCODING_ALGORITHM]', $e->getMessage());
            continue;
          }

          // Crypto operation (raw)
          $aMac = $oDataCryptographer->mac(self::DEFAULT_DATA, true);
          $this->assertArrayHasKey('mac', $aMac);

          // ... payload (see ASCII operation below)

          // ... reverse (same cryptographer)
          $this->assertTrue($oDataCryptographer->macVerify(self::DEFAULT_DATA, $aMac, true));
          $this->assertTrue($oDataCryptographer->macVerify(self::DEFAULT_DATA, $aMac, false));
          $this->assertFalse($oDataCryptographer->macVerify(strrev(self::DEFAULT_DATA), $aMac, true));
          $this->assertFalse($oDataCryptographer->macVerify(strrev(self::DEFAULT_DATA), $aMac, false));

          // Crypto operation (ASCII)
          $sMac = $oDataCryptographer->mac(self::DEFAULT_DATA, false);
          $this->assertStringStartsWith($sHeader, $sMac);
          $sPayload = substr($sMac, strlen($sHeader));

          // ... binary
          $aBinary = $oDataCryptographer->macAscii2Binary($sMac);
          $this->assertArrayHasKey('header', $aBinary);
          $this->assertArrayHasKey('payload', $aBinary);

          // ... header
          $aHeader = $aBinary['header'];
          $this->assertArrayHasKey('mac', $aHeader);
          $this->assertEquals($sMacAlgorithm, $aHeader['mac']);

          // ... payload
          $aPayload = $aBinary['payload'];
          $this->assertArrayHasKey('mac', $aPayload);
          switch (substr($sHeader, -5)) {
          case ':B64}':
            $this->assertEquals(base64_decode($sPayload), $aPayload['mac']);
            break;
          case ':HEX}':
            $this->assertEquals(hex2bin($sPayload), $aPayload['mac']);
            break;
          default:
            $this->assertEquals($sPayload, $aPayload['mac']);
            break;
          }
          switch ($sMacAlgorithm) {
          case '-':
            $this->assertEquals(self::DEFAULT_DATA, $aPayload['mac']);
            break;
          case 'HMD5':
          case 'HSHA1':
          case 'HSHA224':
          case 'HSHA256':
          case 'HSHA384':
          case 'HSHA512':
            $this->assertEquals(hash_hmac($aMacAlgorithm[1], self::DEFAULT_DATA, $sMacKey, true), $aPayload['mac']);
            break;
          default:
            $this->assertEquals($sMacAlgorithm, 'Unknown algorithm');
            break;
          }

          // ... reverse (same cryptographer)
          $this->assertTrue($oDataCryptographer->macVerify(self::DEFAULT_DATA, $sMac, true));
          $this->assertTrue($oDataCryptographer->macVerify(self::DEFAULT_DATA, $sMac, false));
          $this->assertFalse($oDataCryptographer->macVerify(strrev(self::DEFAULT_DATA), $sMac, true));
          $this->assertFalse($oDataCryptographer->macVerify(strrev(self::DEFAULT_DATA), $sMac, false));

          // ... reverse (password-matching sibling)
          $oDataCryptographer = @$oDataCryptographer->getSibling(self::DEFAULT_PASSWORD);
          $this->assertTrue($oDataCryptographer->macVerify(self::DEFAULT_DATA, $sMac, true));
          $this->assertTrue($oDataCryptographer->macVerify(self::DEFAULT_DATA, $sMac, false));
          $this->assertFalse($oDataCryptographer->macVerify(strrev(self::DEFAULT_DATA), $sMac, true));
          $this->assertFalse($oDataCryptographer->macVerify(strrev(self::DEFAULT_DATA), $sMac, false));

          // ... reverse (new generic password-matching cryptographer)
          $oDataCryptographer = @new DataCryptographer(
            self::DEFAULT_PASSWORD,
            $sPasswordAlgorithm,
            self::DEFAULT_PASSWORD_ITERATIONS,
            self::DEFAULT_HASH_ALGORITHM,
            self::DEFAULT_KEY_ALGORITHM,
            self::DEFAULT_KEY_ITERATIONS,
            self::DEFAULT_MAC_ALGORITHM,
            self::DEFAULT_MAC_SALT,
            self::DEFAULT_CIPHER_ALGORITHM,
            self::DEFAULT_CIPHER_SALT,
            false
          );
          $this->assertTrue($oDataCryptographer->macVerify(self::DEFAULT_DATA, $sMac, true));
          $this->assertTrue($oDataCryptographer->macVerify(self::DEFAULT_DATA, $sMac, false));
          $this->assertFalse($oDataCryptographer->macVerify(strrev(self::DEFAULT_DATA), $sMac, true));
          $this->assertFalse($oDataCryptographer->macVerify(strrev(self::DEFAULT_DATA), $sMac, false));

          // ... reverse (password-mismatching sibling)
          if ($sMacAlgorithm!='-') {
            $oDataCryptographer = @$oDataCryptographer->getSibling(strrev(self::DEFAULT_PASSWORD));
            $this->assertFalse($oDataCryptographer->macVerify(self::DEFAULT_DATA, $sMac, true));
            $this->assertFalse($oDataCryptographer->macVerify(self::DEFAULT_DATA, $sMac, false));
            $this->assertFalse($oDataCryptographer->macVerify(strrev(self::DEFAULT_DATA), $sMac, true));
            $this->assertFalse($oDataCryptographer->macVerify(strrev(self::DEFAULT_DATA), $sMac, false));
          }

        }
      }
    }

  }

  public function testCipher() {

    // Loop through supported (internal)key/cipher/MAC/encoding algorithms
    foreach (DataCryptographer::KEY_ALGORITHMS as $sPasswordAlgorithm => $aPasswordAlgorithm) {
      foreach (DataCryptographer::CIPHER_ALGORITHMS as $sCipherAlgorithm => $aCipherAlgorithm) {
        switch ($aPasswordAlgorithm[0]) {
        case null:
          $sCipherKey = self::DEFAULT_PASSWORD;
          break;
        case 'PBKDF2':
          $sCipherKey = hash_pbkdf2($aPasswordAlgorithm[1], self::DEFAULT_PASSWORD, self::DEFAULT_CIPHER_SALT, self::DEFAULT_PASSWORD_ITERATIONS, DataCryptographer::KEY_SIZE_INTERNAL, true);
          break;
        }
        $sCipherKey = substr($sCipherKey, 0, $aCipherAlgorithm[3]);
        foreach (DataCryptographer::MAC_ALGORITHMS as $sMacAlgorithm => $aMacAlgorithm) {
          switch ($aPasswordAlgorithm[0]) {
          case null:
            $sMacKey = self::DEFAULT_PASSWORD;
            break;
          case 'PBKDF2':
            $sMacKey = hash_pbkdf2($aPasswordAlgorithm[1], self::DEFAULT_PASSWORD, self::DEFAULT_MAC_SALT, self::DEFAULT_PASSWORD_ITERATIONS, DataCryptographer::KEY_SIZE_INTERNAL, true);
            break;
          }
          $sMacKey = substr($sMacKey, 0, $aMacAlgorithm[3]);
          foreach (DataCryptographer::ENCODING_ALGORITHMS as $sEncodingAlgorithm => $aEncodingAlgorithm) {
            $sHeader = sprintf('{%s:%s:%s}', $sCipherAlgorithm, $sMacAlgorithm, $sEncodingAlgorithm);
            print("\nCIPHER".$sHeader);

            // Instantiate cryptographer (NB: ignore warnings about NULL algorithms)
            $oDataCryptographer = @new DataCryptographer(
              self::DEFAULT_PASSWORD,
              $sPasswordAlgorithm,
              self::DEFAULT_PASSWORD_ITERATIONS,
              '-',
              '-',
              self::DEFAULT_KEY_ITERATIONS,
              $sMacAlgorithm,
              self::DEFAULT_MAC_SALT,
              $sCipherAlgorithm,
              self::DEFAULT_CIPHER_SALT,
              false
            );
            try {
              $oDataCryptographer->changeEncoding($sEncodingAlgorithm);
            } catch(\Exception $e) {
              $this->assertStringEndsWith('[NO_ENCODING_ALGORITHM]', $e->getMessage());
              continue;
            }

            // Crypto operation (raw)
            $aCipher = $oDataCryptographer->encipher(self::DEFAULT_DATA, true);
            $this->assertArrayHasKey('cipher', $aCipher);
            $this->assertArrayHasKey('iv', $aCipher);
            $this->assertArrayHasKey('mac', $aCipher);

            // ... payload (see ASCII operation below)

            // ... reverse (same cryptographer)
            $this->assertEquals(self::DEFAULT_DATA, $oDataCryptographer->decipher($aCipher, true));
            $this->assertEquals(self::DEFAULT_DATA, $oDataCryptographer->decipher($aCipher, false));
            $this->assertNotEquals(strrev(self::DEFAULT_DATA), $oDataCryptographer->decipher($aCipher, true));
            $this->assertNotEquals(strrev(self::DEFAULT_DATA), $oDataCryptographer->decipher($aCipher, false));

            // Crypto operation (ASCII)
            $sCipher = $oDataCryptographer->encipher(self::DEFAULT_DATA, false);
            $this->assertStringStartsWith($sHeader, $sCipher);
            $sPayload = substr($sCipher, strlen($sHeader));

            // ... binary
            $aBinary = $oDataCryptographer->cipherAscii2Binary($sCipher);
            $this->assertArrayHasKey('header', $aBinary);
            $this->assertArrayHasKey('payload', $aBinary);

            // ... header
            $aHeader = $aBinary['header'];
            $this->assertArrayHasKey('cipher', $aHeader);
            $this->assertArrayHasKey('mac', $aHeader);
            $this->assertEquals($sCipherAlgorithm, $aHeader['cipher']);
            $this->assertEquals($sMacAlgorithm, $aHeader['mac']);

            // ... payload
            $aPayload = $aBinary['payload'];
            $this->assertArrayHasKey('cipher', $aPayload);
            $this->assertArrayHasKey('iv', $aPayload);
            $this->assertArrayHasKey('mac', $aPayload);
            switch (substr($sHeader, -5)) {
            case ':B64}':
              $this->assertEquals(base64_decode($sPayload), $aPayload['cipher'].$aPayload['iv'].$aPayload['mac']);
              break;
            case ':HEX}':
              $this->assertEquals(hex2bin($sPayload), $aPayload['cipher'].$aPayload['iv'].$aPayload['mac']);
              break;
            default:
              $this->assertEquals($sPayload, $aPayload['cipher'].$aPayload['iv'].$aPayload['mac']);
              break;
            }
            switch ($sMacAlgorithm) {
            case '-':
              $this->assertEquals(null, $aPayload['mac']);
              break;
            case 'HMD5':
            case 'HSHA1':
            case 'HSHA224':
            case 'HSHA256':
            case 'HSHA384':
            case 'HSHA512':
              $this->assertEquals(hash_hmac($aMacAlgorithm[1], $aPayload['cipher'].$aPayload['iv'], $sMacKey, true), $aPayload['mac']);
              break;
            default:
              $this->assertEquals($sMacAlgorithm, 'Unknown algorithm');
              break;
            }
            switch ($sCipherAlgorithm) {
            case '-':
              $this->assertEquals(self::DEFAULT_DATA, $aPayload['cipher']);
              break;
            case '3DES':
            case 'AES128':
            case 'AES192':
            case 'AES256':
            case 'BF128':
            case 'BF192':
            case 'BF256':
            case 'BF320':
            case 'BF384':
            case 'BF448':
              $this->assertEquals(openssl_encrypt(self::DEFAULT_DATA, $aCipherAlgorithm[0], $sCipherKey, OPENSSL_RAW_DATA, $aPayload['iv']), $aPayload['cipher']);
              break;
            default:
              $this->assertEquals($sCipherAlgorithm, 'Unknown algorithm');
              break;
            }


            // ... components
            $aComponents = $oDataCryptographer->cipherHeader($sCipher);
            $this->assertArrayHasKey('cipher', $aComponents);
            $this->assertArrayHasKey('mac', $aComponents);
            $this->assertArrayHasKey('payload', $aComponents);

            // ... algorithms
            $this->assertEquals($sCipherAlgorithm, $aComponents['cipher']);
            $this->assertEquals($sMacAlgorithm, $aComponents['mac']);

            // ... payload (if an alternate check procedure exists)
            switch ($sHeader) {
            case '{-:-:-}':
              $this->assertEquals(self::DEFAULT_DATA, $sPayload);
              $this->assertEquals(self::DEFAULT_DATA, $aComponents['payload']);
              break;
            case '{-:-:B64}':
              $this->assertEquals(base64_encode(self::DEFAULT_DATA), $sPayload);
              $this->assertEquals(self::DEFAULT_DATA, $aComponents['payload']);
              break;
            case '{-:-:HEX}':
              $this->assertEquals(bin2hex(self::DEFAULT_DATA), $sPayload);
              $this->assertEquals(self::DEFAULT_DATA, $aComponents['payload']);
              break;
            }

            // ... reverse (same cryptographer)
            $this->assertEquals(self::DEFAULT_DATA, $oDataCryptographer->decipher($sCipher, true));
            $this->assertEquals(self::DEFAULT_DATA, $oDataCryptographer->decipher($sCipher, false));
            $this->assertNotEquals(strrev(self::DEFAULT_DATA), $oDataCryptographer->decipher($sCipher, true));
            $this->assertNotEquals(strrev(self::DEFAULT_DATA), $oDataCryptographer->decipher($sCipher, false));

            // ... reverse (password-matching sibling)
            $oDataCryptographer = @$oDataCryptographer->getSibling(self::DEFAULT_PASSWORD);
            $this->assertEquals(self::DEFAULT_DATA, $oDataCryptographer->decipher($sCipher, true));
            $this->assertEquals(self::DEFAULT_DATA, $oDataCryptographer->decipher($sCipher, false));
            $this->assertNotEquals(strrev(self::DEFAULT_DATA), $oDataCryptographer->decipher($sCipher, true));
            $this->assertNotEquals(strrev(self::DEFAULT_DATA), $oDataCryptographer->decipher($sCipher, false));

            // ... reverse (new generic password-matching cryptographer)
            $oDataCryptographer = @new DataCryptographer(
              self::DEFAULT_PASSWORD,
              $sPasswordAlgorithm,
              self::DEFAULT_PASSWORD_ITERATIONS,
              self::DEFAULT_HASH_ALGORITHM,
              self::DEFAULT_KEY_ALGORITHM,
              self::DEFAULT_KEY_ITERATIONS,
              self::DEFAULT_MAC_ALGORITHM,
              self::DEFAULT_MAC_SALT,
              self::DEFAULT_CIPHER_ALGORITHM,
              self::DEFAULT_CIPHER_SALT,
              false
            );
            $this->assertEquals(self::DEFAULT_DATA, $oDataCryptographer->decipher($sCipher, true));
            $this->assertEquals(self::DEFAULT_DATA, $oDataCryptographer->decipher($sCipher, false));
            $this->assertNotEquals(strrev(self::DEFAULT_DATA), $oDataCryptographer->decipher($sCipher, true));
            $this->assertNotEquals(strrev(self::DEFAULT_DATA), $oDataCryptographer->decipher($sCipher, false));

            // ... reverse (password-mismatching sibling)
            if ($sCipherAlgorithm!='-') {
              $oDataCryptographer = @$oDataCryptographer->getSibling(strrev(self::DEFAULT_PASSWORD));
              try {
                $this->assertNotEquals(self::DEFAULT_DATA, $oDataCryptographer->decipher($sCipher, true));
                $this->assertEquals('-', $sMacAlgorithm);
              } catch(\Exception $e) {
                $this->assertStringEndsWith('[BAD_MAC]', $e->getMessage());
              }
              try {
                $this->assertNotEquals(self::DEFAULT_DATA, $oDataCryptographer->decipher($sCipher, false));
                $this->assertEquals('-', $sMacAlgorithm);
              } catch(\Exception $e) {
                $this->assertStringEndsWith('[BAD_MAC]', $e->getMessage());
              }
              try {
                $this->assertNotEquals(strrev(self::DEFAULT_DATA), $oDataCryptographer->decipher($sCipher, true));
                $this->assertEquals('-', $sMacAlgorithm);
              } catch(\Exception $e) {
                $this->assertStringEndsWith('[BAD_MAC]', $e->getMessage());
              }
              try {
                $this->assertNotEquals(strrev(self::DEFAULT_DATA), $oDataCryptographer->decipher($sCipher, false));
                $this->assertEquals('-', $sMacAlgorithm);
              } catch(\Exception $e) {
                $this->assertStringEndsWith('[BAD_MAC]', $e->getMessage());
              }
            }

          }
        }
      }
    }

  }

}
