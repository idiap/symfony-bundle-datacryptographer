<?php // -*- mode:php; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
// DataCryptographerBundle\DataCryptographer.php

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
 * @copyright  2016 Idiap Research Institute <http://www.idiap.ch>
 * @author     Cedric Dufour <http://cedric.dufour.name>
 * @license    http://www.gnu.org/licenses/gpl-3.0.html GNU General Public License (GPL) Version 3
 * @version    %{VERSION}
 * @link       https://github.com/idiap/symfony-bundle-datacryptographer
 */

namespace DataCryptographerBundle;

/** Data cryptographer class
 *
 * <P>This class wraps the methods required to perform cryptographic operations on data,
 * leveraging both:</P>
 * <UL>
 * <LI>PHP <SAMP>Hash</SAMP> functions, for hash/HMAC/PBKDF2 operations</LI>
 * <LI><SAMP>OpenSSL</SAMP> functions, for cipher operations</LI>
 * </UL>
 * <P>All commonly recognized algorithms are supported; see the class constants for their
 * list and IDs. It may be worth noting that all standard hash algorithms have a "H"-prefixed
 * version which corresponds to their salted variant (then relying on the corresponding HMAC
 * algorithm).</P>
 * <P>Unless explicitely stated otherwise, output of the various "forward" operations
 * are always <B>ASCII (headered/armored)</B> and safe for non-binary data storage/handling:</P>
 * <UL>
 * <LI><B>Hash</B> operations: "{<I>HASH-algorithm</I>:<I>ENCODING-algorithm</I>}<I>HASH</I>+<I>SALT</I>"</LI>
 * <LI><B>MAC</B> operations: "{<I>MAC-algorithm</I>:<I>ENCODING-algorithm</I>}<I>MAC</I>"</LI>
 * <LI><B>Key (derivation)</B> operations: "{<I>KEY-algorithm</I>:<I>ITERATIONS</I>:<I>ENCODING-algorithm</I>}<I>KEY</I>"</LI>
 * <LI><B>Key (hash)</B> operations: "{<I>KEY-algorithm</I>:<I>ITERATIONS</I>:<I>ENCODING-algorithm</I>}<I>KEY</I>+<I>SALT</I>"</LI>
 * <LI><B>Cipher</B> operations: "{<I>CIPHER-algorithm</I>:<I>MAC-algorithm</I>:<I>ENCODING-algorithm</I>}<I>CIPHER</I>+<I>IV</I>+<I>MAC</I>"</LI>
 * </UL>
 * <P>In case the cryptographer is declared as <SAMP>strict</SAMP> (the default), any unsafe
 * configuration parameter will lead to an exception. Also, "reverse" operations will only
 * accept properly headered/armored ASCII input. If explicitely configured as non-strict,
 * the cryptographer will accept ASCII input with lacking or invalid header and consider it
 * as cleartext, iow. as if all algorithms were "-" (No-op). This can be useful for migration
 * of existing data but SHOULD NOT be used otherwise.</P>
 *
 * @see DataCryptographerException
 * @package    DataCryptographerBundle
 */
class DataCryptographer
  implements DataCryptographerInterface
{

  /*
   * CONSTANTS
   ********************************************************************************/

  const HASH_ALGORITHMS = array(
    // 'ID' => array('<hash-ID>', <block-size>, '<salt-ID>', <salt-size>),
    '-' => array(null, 0, null, 0),  // No-op / SHOULD be used only for test or migration purposes!
    'MD5' => array('MD5', 16, null, 0),
    'HMD5' => array('MD5', 16, 'HMAC', 16),
    'SHA1' => array('SHA1', 20, null, 0),
    'HSHA1' => array('SHA1', 20, 'HMAC', 20),
    'SHA224' => array('SHA224', 28, null, 0),
    'HSHA224' => array('SHA224', 28, 'HMAC', 28),
    'SHA256' => array('SHA256', 32, null, 0),
    'HSHA256' => array('SHA256', 32, 'HMAC', 32),
    'SHA384' => array('SHA384', 48, null, 0),
    'HSHA384' => array('SHA384', 48, 'HMAC', 48),
    'SHA512' => array('SHA512', 64, null, 0),
    'HSHA512' => array('SHA512', 64, 'HMAC', 64),
  );

  const KEY_ALGORITHMS = array(
    // 'ID' => array('<derivation-ID>', '<hash-ID>', <block-size>, <salt-size>),
    '-' => array(null, null, 0, 0),  // No-op / SHOULD be used only for test or migration purposes!
    'P2MD5' => array('PBKDF2', 'MD5', 16, 16),
    'P2SHA1' => array('PBKDF2', 'SHA1', 20, 20),
    'P2SHA224' => array('PBKDF2', 'SHA224', 28, 28),
    'P2SHA256' => array('PBKDF2', 'SHA256', 32, 32),
    'P2SHA384' => array('PBKDF2', 'SHA384', 48, 48),
    'P2SHA512' => array('PBKDF2', 'SHA512', 64, 64),
  );

  const MAC_ALGORITHMS = array(
    // 'ID' => array('MAC-ID', '<hash-ID>', <block-size>, <key-size>),
    '-' => array(null, null, 0, 0),  // No-op / SHOULD be used only for test or migration purposes!
    'HMD5' => array('HMAC', 'MD5', 16, 16),
    'HSHA1' => array('HMAC', 'SHA1', 20, 20),
    'HSHA224' => array('HMAC', 'SHA224', 28, 28),
    'HSHA256' => array('HMAC', 'SHA256', 32, 32),
    'HSHA384' => array('HMAC', 'SHA384', 48, 48),
    'HSHA512' => array('HMAC', 'SHA512', 64, 64),
  );

  const CIPHER_ALGORITHMS = array(
    // 'ID' => array('<OpenSSL-ID>', <block-size>, <IV-size>, <key-size>),
    '-' => array(null, 0, 0, 0),  // No-op / SHOULD be used only for test or migration purposes!
    '3DES' => array('DES-EDE3-CBC', 8, 8, 21),
    'AES128' => array('AES-128-CBC', 16, 16, 16),
    'AES192' => array('AES-192-CBC', 16, 16, 24),
    'AES256' => array('AES-256-CBC', 16, 16, 32),
    'BF128' => array('BF-CBC', 8, 8, 16),
    'BF192' => array('BF-CBC', 8, 8, 24),
    'BF256' => array('BF-CBC', 8, 8, 32),
    'BF320' => array('BF-CBC', 8, 8, 40),
    'BF384' => array('BF-CBC', 8, 8, 48),
    'BF448' => array('BF-CBC', 8, 8, 56),
  );

  const ENCODING_ALGORITHMS = array(
    // 'ID' => array('<encoding-function>', '<decoding-function>'),
    '-' => array(null, null),  // No-op / SHOULD be used only for test or migration purposes!
    'B64' => array('base64_encode', 'base64_decode'),
    'HEX' => array('bin2hex', 'hex2bin'),
  );

  const KEY_SIZE_INTERNAL = 256;  // let's use the maximum foreseeable key size, to allow seamless algorithm change


  /*
   * STATIC
   ********************************************************************************/

  protected static function _warning($sMessage, $bException=false)
  {
    if ($bException) {
      throw new DataCryptographerException($sMessage);
    }
    trigger_error($sMessage, E_USER_WARNING);
  }


  /*
   * PROPERTIES
   ********************************************************************************/

  /** Password <-> internal key (derivation) algorithm identifier
   * @var string
   */
  private $sPasswordAlgorithm;

  /** Password <-> internal key (derivation) iterations count
   * @var integer
   */
  private $iPasswordIterations;

  /** Hash algorithm identifier
   * @var string
   */
  protected $sHashAlgorithm;

  /** Key (derivation) algorithm identifier
   * @var string
   */
  protected $sKeyAlgorithm;

  /** Key (derivation) iterations count
   * @var integer
   */
  protected $iKeyIterations;

  /** MAC algorithm identifier
   * @var string
   */
  protected $sMacAlgorithm;

  /** MAC salt
   * @var string
   */
  private $sMacSalt;

  /** MAC (derived) key
   * @var string
   */
  private $sMacKey;

  /** Cipher algorithm identifier
   * @var string
   */
  protected $sCipherAlgorithm;

  /** Cipher salt
   * @var string
   */
  private $sCipherSalt;

  /** Cipher (derived) key
   * @var string
   */
  private $sCipherKey;

  /** Strict mode
   * @var boolean
   */
  protected $bStrict;

  /** Encoding algorithm identifier
   * @var string
   */
  protected $sEncodingAlgorithm;


  /*
   * CONSTUCTORS/DESTRUCTOR
   ********************************************************************************/

  /** Constructor
   *
   * <P>About internal key derivation: internal cipher and MAC keys are derived
   * from the given password using the specified key (derivation) algorithm, each
   * with their given corresponding salt.<BR/>
   * Generally speaking, the number of iterations should be high enough to prevent
   * brute-force attacks.<BR/>
   * However, for cryptographic operations used when generating PHP pages (rather than,
   * exemple given, a one time file or stream operation), specifying a high number of
   * iterations will dramatically load the CPU and slow down pages generation; for this
   * specific purpose, it is thus recommended to keep that number very low.</P>
   *
   * @param string $sPassword Password (from which the internal cipher/MAC keys will be derived)
   * @param string $sPasswordAlgorithm Password <-> internal key (derivation) algorithm ID
   * @param integer $iPasswordIterations Password <-> internal key (derivation) iterations count
   * @param string $sHashAlgorithm Hash (digest/integrity code) algorithm ID
   * @param string $sKeyAlgorithm Key (derivation/hash) algorithm ID
   * @param integer $iKeyIterations Key (derivation/hash) iterations count
   * @param string $sMacAlgorithm MAC (authentication code) algorithm ID
   * @param string $sMacSalt MAC (authentication code) key derivation salt
   * @param string $sCipherAlgorithm Cipher (encryption/decryption) algorithm ID
   * @param string $sCipherSalt Cipher (encryption/decryption) key derivation salt
   * @param boolean $bStrict Strict mode
   */
  public function __construct(
    $sPassword,
    $sPasswordAlgorithm,
    $iPasswordIterations,
    $sHashAlgorithm,
    $sKeyAlgorithm,
    $iKeyIterations,
    $sMacAlgorithm,
    $sMacSalt,
    $sCipherAlgorithm,
    $sCipherSalt,
    $bStrict = true
  )
  {
    // Normalize input
    switch (substr($sPassword, 0, 5)) {
    case '{HEX}': $sPassword = hex2bin(substr($sPassword, 5)); break;
    case '{B64}': $sPassword = base64_decode(substr($sPassword, 5)); break;
    }
    $sPasswordAlgorithm = strtoupper($sPasswordAlgorithm);
    $iPasswordIterations = (integer)$iPasswordIterations;
    $sHashAlgorithm = strtoupper($sHashAlgorithm);
    $sKeyAlgorithm = strtoupper($sKeyAlgorithm);
    $iKeyIterations = (integer)$iKeyIterations;
    $sMacAlgorithm = strtoupper($sMacAlgorithm);
    switch (substr($sMacSalt, 0, 5)) {
    case '{HEX}': $sMacSalt = hex2bin(substr($sMacSalt, 5)); break;
    case '{B64}': $sMacSalt = base64_decode(substr($sMacSalt, 5)); break;
    }
    $sCipherAlgorithm = strtoupper($sCipherAlgorithm);
    switch (substr($sCipherSalt, 0, 5)) {
    case '{HEX}': $sCipherSalt = hex2bin(substr($sCipherSalt, 5)); break;
    case '{B64}': $sCipherSalt = base64_decode(substr($sCipherSalt, 5)); break;
    }
    $bStrict = (boolean)$bStrict;

    // Check parameters (we don't want a half-baked cryptographer)
    if (!strlen($sPassword)) {
      self::_warning('No password [NO_PASSWORD]', $bStrict);
    }
    if (!array_key_exists($sPasswordAlgorithm, self::KEY_ALGORITHMS)) {
      self::_warning(sprintf('Invalid password <-> internal key (derivation) algorithm (%s) [INVALID_PASSWORD_ALGORITHM]', $sPasswordAlgorithm), true);
    }
    if ($sPasswordAlgorithm=='-') {
      self::_warning('No-op password <-> internal key (derivation) algorithm [NO_PASSWORD_ALGORITHM]', $bStrict);
    } elseif ($iPasswordIterations<=0) {
      self::_warning(sprintf('Invalid password <-> internal key (derivation) iterations count (%d) [INVALID_PASSWORD_ITERATIONS]', $iPasswordIterations), true);
    }
    if (!array_key_exists($sHashAlgorithm, self::HASH_ALGORITHMS)) {
      self::_warning(sprintf('Invalid hash algorithm (%s) [INVALID_HASH_ALGORITHM]', $sHashAlgorithm), true);
    }
    if ($sHashAlgorithm=='-') {
      self::_warning('No-op hash algorithm [NO_HASH_ALGORITHM]', $bStrict);
    }
    if (!array_key_exists($sKeyAlgorithm, self::KEY_ALGORITHMS)) {
      self::_warning(sprintf('Invalid key (derivation) algorithm (%s) [INVALID_KEY_ALGORITHM]', $sKeyAlgorithm), true);
    }
    if ($sKeyAlgorithm=='-') {
      self::_warning('No-op key (derivation) algorithm [NO_KEY_ALGORITHM]', $bStrict);
    } elseif ($iKeyIterations<=0) {
      self::_warning(sprintf('Invalid key (derivation) iterations (%d) [INVALID_KEY_ITERATIONS]', $iKeyIterations), true);
    }
    if (!array_key_exists($sMacAlgorithm, self::MAC_ALGORITHMS)) {
      self::_warning(sprintf('Invalid MAC algorithm (%s) [INVALID_MAC_ALGORITHM]', $sMacAlgorithm), true);
    }
    if ($sMacAlgorithm=='-') {
      self::_warning('No-op MAC algorithm [NO_MAC_ALGORITHM]', $bStrict);
    } elseif (!strlen($sMacSalt)) {
      self::_warning('No MAC salt [NO_MAC_SALT]', $bStrict);
    }
    if (!array_key_exists($sCipherAlgorithm, self::CIPHER_ALGORITHMS)) {
      self::_warning(sprintf('Invalid cipher algorithm (%s) [INVALID_CIPHER_ALGORITHM]', $sCipherAlgorithm), true);
    }
    if ($sCipherAlgorithm=='-') {
      self::_warning('No-op cipher algorithm [NO_CIPHER_ALGORITHM]', $bStrict);
    } elseif (!strlen($sCipherSalt)) {
      self::_warning('No cipher salt [NO_CIPHER_SALT]', $bStrict);
    }

    // Save parameters
    $this->sPasswordAlgorithm = $sPasswordAlgorithm;
    $this->iPasswordIterations = $iPasswordIterations;
    $this->sHashAlgorithm = $sHashAlgorithm;
    $this->sKeyAlgorithm = $sKeyAlgorithm;
    $this->iKeyIterations = $iKeyIterations;
    $this->sMacAlgorithm = $sMacAlgorithm;
    $this->sMacSalt = $sMacSalt;
    $this->sCipherAlgorithm = $sCipherAlgorithm;
    $this->sCipherSalt = $sCipherSalt;
    $this->sEncodingAlgorithm = 'B64';

    // Keys
    switch (self::KEY_ALGORITHMS[$this->sPasswordAlgorithm][0]) {

    case 'PBKDF2':
      $this->sMacKey = hash_pbkdf2(
        self::KEY_ALGORITHMS[$this->sPasswordAlgorithm][1],
        $sPassword,
        $this->sMacSalt,
        $this->iPasswordIterations,
        self::KEY_SIZE_INTERNAL,
        true
      );
      $this->sCipherKey = hash_pbkdf2(
        self::KEY_ALGORITHMS[$this->sPasswordAlgorithm][1],
        $sPassword,
        $this->sCipherSalt,
        $this->iPasswordIterations,
        self::KEY_SIZE_INTERNAL,
        true
      );
      break;

    case null:
      $this->sMacKey = $sPassword;
      $this->sCipherKey = $sPassword;
      break;

    }

    // Misc
    $this->bStrict = $bStrict;
  }

  /** Returns a copy of this cryptographer (with an alternate password)
   *
   * @param string $sPassword Password (from which the cipher/MAC keys will be derived)
   * @param string $sPasswordAlgorithm Internal key (derivation) algorithm ID (defaults to the parent setting if NULL/unspecified)
   * @param integer $iPasswordIterations Internal key (derivation) iterations count (defaults to the parent setting if NULL/unspecified)
   * @param string $sMacSalt MAC (authentication code) key derivation salt (defaults to the parent setting if NULL/unspecified)
   * @param string $sCipherSalt Cipher (encryption/decryption) key derivation salt (defaults to the parent setting if NULL/unspecified)
   * @param boolean $bStrict Strict mode (defaults to the parent setting if NULL/unspecified)
   */
  public function getSibling($sPassword, $sPasswordAlgorithm=null, $iPasswordIterations=null, $sMacSalt=null, $sCipherSalt=null, $bStrict=null)
  {
    $oCryptographer = new DataCryptographer(
      $sPassword,
      !is_null($sPasswordAlgorithm) ? $sPasswordAlgorithm : $this->sPasswordAlgorithm,
      !is_null($iPasswordIterations) ? $iPasswordIterations : $this->iPasswordIterations,
      $this->sHashAlgorithm,
      $this->sKeyAlgorithm,
      $this->iKeyIterations,
      $this->sMacAlgorithm,
      !is_null($sMacSalt) ? $sMacSalt : $this->sMacSalt,
      $this->sCipherAlgorithm,
      !is_null($sCipherSalt) ? $sCipherSalt : $this->sCipherSalt,
      !is_null($bStrict) ? $bStrict : $this->bStrict
    );
    $oCryptographer->changeEncoding($this->sEncodingAlgorithm);
    return $oCryptographer;
  }


  /*
   * METHODS
   ********************************************************************************/

  /** Parses, validates and returns the given ASCII (headered/armored) hash header and payload components
   *
   * <P>This method parses the given hash and looks for the <SAMP>{HASH:ENCODING}</SAMP>
   * identifiers of the algorithms used to perform the hash and encoding.<BR/>
   * On success, it returns a bi-dimensional <B>array</B>, associating:</P>
   * <UL>
   * <LI><B>header</B>/<B>hash</B>: hash algorithm identifier</LI>
   * <LI><B>payload</B>/<B>hash</B>: hash binary value</LI>
   * <LI><B>payload</B>/<B>salt</B>: salt binary value</LI>
   * </UL>
   * <P>Or <B>NULL</B> if no valid header/payload can be found.</P>
   *
   * @param string $sHash ASCII (headered/armored) hash
   * @return array Hash components
   */
  public function hashAscii2Binary($sHash)
  {
    $sSalt = null;

    // Header
    $aHeader = $this->hashHeader($sHash);
    if (is_array($aHeader)) {
      $sHashAlgorithm = $aHeader['hash'];
      $sHash = $aHeader['payload'];
    } else {
      self::_warning('Invalid input (missing/corrupted header/payload) [INVALID_INPUT]', $this->bStrict);
      $sHashAlgorithm = '-';
    }

    // Salt
    if (self::HASH_ALGORITHMS[$sHashAlgorithm][3]) {
      if (strlen($sHash)>=self::HASH_ALGORITHMS[$sHashAlgorithm][3]) {
        $sSalt = substr($sHash, -self::HASH_ALGORITHMS[$sHashAlgorithm][3]);
        $sHash = substr($sHash, 0, -self::HASH_ALGORITHMS[$sHashAlgorithm][3]);
      } else {
        self::_warning('Invalid input (missing/incomplete salt) [NO_SALT]', $this->bStrict);
        return null;
      }
    }

    // Hash
    if (self::HASH_ALGORITHMS[$sHashAlgorithm][1] and strlen($sHash)!=self::HASH_ALGORITHMS[$sHashAlgorithm][1]) {
      self::_warning('Invalid input (missing/incomplete hash) [NO_HASH]', $this->bStrict);
      return null;
    }

    // Done
    return array(
      'header' => array(
        'hash' => $sHashAlgorithm,
      ),
      'payload' => array(
        'hash' => $sHash,
        'salt' => $sSalt,
      ),
    );
  }

  /** Parses, validates and returns the given ASCII (headered/armored) key header and payload components
   *
   * <P>This method parses the given key and looks for the <SAMP>{KEY:ITERATIONS:ENCODING}</SAMP>
   * identifiers of the algorithms used to perform the key derivation and encoding.<BR/>
   * On success, it returns a bi-dimensional <B>array</B>, associating:</P>
   * <UL>
   * <LI><B>header</B>/<B>key</B>: key algorithm identifier</LI>
   * <LI><B>header</B>/<B>iterations</B>: key derivation iterations</LI>
   * <LI><B>payload</B>/<B>key</B>: key binary value</LI>
   * <LI><B>payload</B>/<B>salt</B>: salt binary value (for key hashes)</LI>
   * </UL>
   * <P>Or <B>NULL</B> if no valid header/payload can be found.</P>
   *
   * @param string $sKey ASCII (headered/armored) key
   * @param string $sSalt Key salt
   * @return array Key components
   */
  public function keyAscii2Binary($sKey, $sSalt=null)
  {
    $bUseRandomSalt = is_null($sSalt);

    // Header
    $aHeader = $this->keyHeader($sKey);
    if (is_array($aHeader)) {
      $sKeyAlgorithm = $aHeader['key'];
      $iKeyIterations = $aHeader['iterations'];
      $sKey = $aHeader['payload'];
    } else {
      self::_warning('Invalid input (missing/corrupted header/payload) [INVALID_INPUT]', $this->bStrict);
      $sKeyAlgorithm = '-';
    }

    // Salt
    if ($bUseRandomSalt and self::KEY_ALGORITHMS[$sKeyAlgorithm][3]) {
      if (strlen($sKey)>=self::KEY_ALGORITHMS[$sKeyAlgorithm][3]) {
        $sSalt = substr($sKey, -self::KEY_ALGORITHMS[$sKeyAlgorithm][3]);
        $sKey = substr($sKey, 0, -self::KEY_ALGORITHMS[$sKeyAlgorithm][3]);
      } else {
        self::_warning('Invalid input (missing/incomplete salt) [NO_SALT]', $this->bStrict);
        return null;
      }
    }

    // Key
    if (self::KEY_ALGORITHMS[$sKeyAlgorithm][2] and strlen($sKey)!=self::KEY_ALGORITHMS[$sKeyAlgorithm][2]) {
      self::_warning('Invalid input (missing/incomplete key) [NO_KEY]', $this->bStrict);
      return null;
    }

    // Done
    return array(
      'header' => array(
        'key' => $sKeyAlgorithm,
        'iterations' => $iKeyIterations,
      ),
      'payload' => array(
        'key' => $sKey,
        'salt' => $sSalt,
      ),
    );
  }

  /** Parses, validates and returns the given ASCII (headered/armored) MAC header and payload components
   *
   * <P>This method parses the given MAC and looks for the <SAMP>{MAC:ENCODING}</SAMP>
   * identifiers of the algorithms used to perform the MAC and encoding.<BR/>
   * On success, it returns a bi-dimensional <B>array</B>, associating:</P>
   * <UL>
   * <LI><B>header</B>/<B>mac</B>: MAC algorithm identifier</LI>
   * <LI><B>payload</B>/<B>mac</B>: MAC binary value</LI>
   * </UL>
   * <P>Or <B>NULL</B> if no valid header/payload can be found.</P>
   *
   * @param string $sMAC ASCII (headered/armored) MAC
   * @return array MAC components
   */
  public function macAscii2Binary($sMac)
  {
    // Header
    $aHeader = $this->macHeader($sMac);
    if (is_array($aHeader)) {
      $sMacAlgorithm = $aHeader['mac'];
      $sMac = $aHeader['payload'];
    } else {
      self::_warning('Invalid input (missing/corrupted header/payload) [INVALID_INPUT]', $this->bStrict);
      $sMacAlgorithm = '-';
    }

    // MAC
    if (self::MAC_ALGORITHMS[$sMacAlgorithm][2] and strlen($sMac)!=self::MAC_ALGORITHMS[$sMacAlgorithm][2]) {
      self::_warning('Invalid input (missing/incomplete MAC) [NO_MAC]', $this->bStrict);
      return null;
    }

    // Done
    return array(
      'header' => array(
        'mac' => $sMacAlgorithm,
      ),
      'payload' => array(
        'mac' => $sMac,
      ),
    );
  }

  /** Parses, validates and returns the given ASCII (headered/armored) cipher header and payload components
   *
   * <P>This method parses the given cipher and looks for the <SAMP>{CIPHER:MAC:ENCODING}</SAMP>
   * identifiers of the algorithms used to perform the encipherment and encoding.<BR/>
   * On success, it returns bi-dimensional <B>array</B>, associating:</P>
   * <UL>
   * <LI><B>header</B>/<B>cipher</B>: cipher algorithm identifier</LI>
   * <LI><B>header</B>/<B>mac</B>: MAC algorithm identifier</LI>
   * <LI><B>payload</B>/<B>cipher</B>: cipher binary value</LI>
   * <LI><B>payload</B>/<B>iv</B>: initialization vector (IV) binary value</LI>
   * <LI><B>payload</B>/<B>mac</B>: MAC binary value</LI>
   * </UL>
   * <P>Or <B>NULL</B> if no valid header can be found.</P>
   *
   * @param string $sCipher ASCII (headered/armored) cipher
   * @return array Cipher components
   */
  public function cipherAscii2Binary($sCipher)
  {
    $sMac = null;
    $sIv = null;

    // Header
    $aHeader = $this->cipherHeader($sCipher);
    if (is_array($aHeader)) {
      $sCipherAlgorithm = $aHeader['cipher'];
      $sMacAlgorithm = $aHeader['mac'];
      $sCipher = $aHeader['payload'];
    } else {
      self::_warning('Invalid input (missing/corrupted header/payload) [INVALID_INPUT]', $this->bStrict);
      $sCipherAlgorithm = '-';
      $sMacAlgorithm = '-';
    }

    // MAC
    if (self::MAC_ALGORITHMS[$sMacAlgorithm][2]) {
      if (strlen($sCipher)>=self::MAC_ALGORITHMS[$sMacAlgorithm][2]) {
        $sMac = substr($sCipher, -self::MAC_ALGORITHMS[$sMacAlgorithm][2]);
        $sCipher = substr($sCipher, 0, -self::MAC_ALGORITHMS[$sMacAlgorithm][2]);
      } else {
        self::_warning('Invalid input (missing/incomplete MAC) [NO_MAC]', $this->bStrict);
        return null;
      }
    }

    // IV
    if (self::CIPHER_ALGORITHMS[$sCipherAlgorithm][2]) {
      if (strlen($sCipher)>=self::CIPHER_ALGORITHMS[$sCipherAlgorithm][2]) {
        $sIv = substr($sCipher, -self::CIPHER_ALGORITHMS[$sCipherAlgorithm][2]);
        $sCipher = substr($sCipher, 0, -self::CIPHER_ALGORITHMS[$sCipherAlgorithm][2]);
      } else {
        self::_warning('Invalid input (missing/incomplete IV) [NO_IV]', $this->bStrict);
        return null;
      }
    }

    // Cipher
    if (strlen($sCipher)<self::CIPHER_ALGORITHMS[$sCipherAlgorithm][1]) {
      self::_warning('Invalid input (missing/incomplete cipher) [NO_CIPHER]', $this->bStrict);
      return null;
    }

    // Done
    return array(
      'header' => array(
        'cipher' => $sCipherAlgorithm,
        'mac' => $sMacAlgorithm,
      ),
      'payload' => array(
        'cipher' => $sCipher,
        'iv' => $sIv,
        'mac' => $sMac,
      ),
    );
  }

  /** Change the encoding algorithm from its default (not recommended)
   *
   * @param string $sEncodingAlgorithm Encoding algorithm ID
   */
  public function changeEncoding($sEncodingAlgorithm)
  {
    $sEncodingAlgorithm = strtoupper($sEncodingAlgorithm);
    if (!array_key_exists($sEncodingAlgorithm, self::ENCODING_ALGORITHMS)) {
      self::_warning(sprintf('Invalid encoding algorithm (%s) [INVALID_ENCODING_ALGORITHM]', $sEncodingAlgorithm), true);
    }
    if ($sEncodingAlgorithm=='-') {
      self::_warning('No-op encoding algorithm [NO_ENCODING_ALGORITHM]', $this->bStrict or $this->sHashAlgorithm!='-' or $this->sKeyAlgorithm!='-' or $this->sMacAlgorithm!='-' or $this->sCipherAlgorithm!='-');
    }
    $this->sEncodingAlgorithm = $sEncodingAlgorithm;
  }

  /** Encodes the given input
   *
   * @param string $sInput Input to encode
   * @param string $sEncodingAlgorithm Encoding algorithm ID (using the default encoding if NULL/unspecified)
   * @return string Encoded string
   */
  public function encode($sInput, $sEncodingAlgorithm=null)
  {
    switch (!is_null($sEncodingAlgorithm) ? $sEncodingAlgorithm : $this->sEncodingAlgorithm) {
    case 'B64': return base64_encode($sInput);
    case 'HEX': return bin2hex($sInput);
    case '-': return $sInput;
    }
    return null;
  }

  /** Decodes the given input
   *
   * @param string $sInput Input to decode
   * @param string $sEncodingAlgorithm Encoding algorithm ID (using the default encoding if NULL/unspecified)
   * @return string Decoded string
   */
  public function decode($sInput, $sEncodingAlgorithm=null)
  {
    switch (!is_null($sEncodingAlgorithm) ? $sEncodingAlgorithm : $this->sEncodingAlgorithm) {
    case 'B64': return base64_decode($sInput, true);
    case 'HEX': return hex2bin($sInput);
    case '-': return $sInput;
    }
    return null;
  }


  /*
   * METHODS: DataCryptographerInterface
   ********************************************************************************/

  /**
   * {@inheritdoc}
   */
  public function hash($sInput, $bRaw=false)
  {
    switch (self::HASH_ALGORITHMS[$this->sHashAlgorithm][2]) {

    case 'HMAC':
      $sSalt = openssl_random_pseudo_bytes(self::HASH_ALGORITHMS[$this->sHashAlgorithm][3]);
      $sHash = hash_hmac(
        self::HASH_ALGORITHMS[$this->sHashAlgorithm][0],
        $sInput,
        $sSalt,
        true
      );
      break;

    case null:
      $sSalt = null;
      $sHash =
        $this->sHashAlgorithm!='-'
        ? hash(
          self::HASH_ALGORITHMS[$this->sHashAlgorithm][0],
          $sInput,
          true
        )
        : $sInput;
      break;

    }
    return
      $bRaw
      ? array('hash' => $sHash, 'salt' => $sSalt)
      : preg_replace(
        '/^\{([^:]+)(:-)+\}/',
        '{$1}',
        sprintf(
          '{%s:%s}%s',
          $this->sHashAlgorithm,
          $this->sEncodingAlgorithm,
          $this->encode($sHash.$sSalt)
        )
      );
  }

  /**
   * {@inheritdoc}
   */
  public function hashHeader($sHash)
  {
    // Header
    $sHash = (string)$sHash;
    if ($sHash[0]!='{') return null;
    $i = strpos($sHash, '}');
    if ($i===false) return null;
    $sHeader = substr($sHash, 1, $i-1);
    $sEncodingAlgorithm = '-';
    $j = strpos($sHeader, ':');
    if ($j===false) {
      $sHashAlgorithm = $sHeader;
    } else {
      $sHashAlgorithm = substr($sHeader, 0, $j);
      $sEncodingAlgorithm = (string)substr($sHeader, $j+1);  // NB: index overflow leads to (boolean)false
    }

    // Check algorithms
    if (!array_key_exists($sHashAlgorithm, self::HASH_ALGORITHMS)) return null;
    if (!array_key_exists($sEncodingAlgorithm, self::ENCODING_ALGORITHMS)) return null;

    // Payload
    $sPayload = $this->decode(substr($sHash, $i+1), $sEncodingAlgorithm);
    if ($sPayload===false) return null;

    // Done
    return array(
      'hash' => $sHashAlgorithm,
      'payload' => $sPayload,
    );
  }

  /**
   * {@inheritdoc}
   */
  public function hashVerify($sInput, $mHash, $bTimeInvariant=true)
  {
    $sHashAlgorithm = $this->sHashAlgorithm;
    if (is_array($mHash)) {
      // Raw (binary) input

      $sHash = $mHash['hash'];
      $sSalt = $mHash['salt'];

    } else {
      // ASCII

      $mHash = $this->hashAscii2Binary($mHash);
      if (!is_array($mHash)) return $bTimeInvariant ? hash_equals('not', 'equal') : false;
      $sHashAlgorithm = $mHash['header']['hash'];
      $sHash = $mHash['payload']['hash'];
      $sSalt = $mHash['payload']['salt'];

    }

    // Check hash
    switch (self::HASH_ALGORITHMS[$sHashAlgorithm][2]) {

    case 'HMAC':
      $sHash_input = hash_hmac(
        self::HASH_ALGORITHMS[$sHashAlgorithm][0],
        $sInput,
        $sSalt,
        true
      );
      break;

    case null:
      $sHash_input =
        $sHashAlgorithm!='-'
        ? hash(
          self::HASH_ALGORITHMS[$sHashAlgorithm][0],
          $sInput,
          true
        )
        : $sInput;
      break;

    }
    return $bTimeInvariant ? hash_equals($sHash, $sHash_input) : ($sHash==$sHash_input);
  }

  /**
   * {@inheritdoc}
   */
  public function key($sInput, $sSalt=null, $bRaw=false)
  {
    $bUseRandomSalt = is_null($sSalt);
    switch (self::KEY_ALGORITHMS[$this->sKeyAlgorithm][0]) {

    case 'PBKDF2':
      if ($bUseRandomSalt) $sSalt = openssl_random_pseudo_bytes(self::KEY_ALGORITHMS[$this->sKeyAlgorithm][3]);
      $sKey = hash_pbkdf2(
        self::KEY_ALGORITHMS[$this->sKeyAlgorithm][1],
        $sInput,
        $sSalt,
        $this->iKeyIterations,
        0,
        true
      );
      break;

    case null:
      $sSalt = null;
      $sKey = $sInput;
      break;

    }
    return
      $bRaw
      ? array('key' => $sKey, 'salt' => $sSalt)
      : preg_replace(
        '/^\{([^:]+:\d+)(:-)+\}/',
        '{$1}',
        sprintf(
          '{%s:%d:%s}%s',
          $this->sKeyAlgorithm,
          $this->iKeyIterations,
          $this->sEncodingAlgorithm,
          $this->encode($bUseRandomSalt ? $sKey.$sSalt : $sKey)
        )
      );
  }

  /**
   * {@inheritdoc}
   */
  public function keyHeader($sKey)
  {
    // Header
    $sKey = (string)$sKey;
    if ($sKey[0]!='{') return null;
    $i = strpos($sKey, '}');
    if ($i===false) return null;
    $sHeader = substr($sKey, 1, $i-1);
    $sKeyAlgorithm = '-';
    $iKeyIterations = 1;
    $sEncodingAlgorithm = '-';
    $j = strpos($sHeader, ':');
    if ($j===false) {
      $sKeyAlgorithm = $sHeader;
    } else {
      $sKeyAlgorithm = substr($sHeader, 0, $j);
      $sHeader = (string)substr($sHeader, $j+1);  // NB: index overflow leads to (boolean)false
      $k = strpos($sHeader, ':');
      if ($k===false) {
        $iKeyIterations = (integer)$sHeader;
      } else {
        $iKeyIterations = (integer)substr($sHeader, 0, $k);
        $sEncodingAlgorithm = (string)substr($sHeader, $k+1);  // NB: index overflow leads to (boolean)false
      }
    }

    // Check algorithms
    if (!array_key_exists($sKeyAlgorithm, self::KEY_ALGORITHMS)) return null;
    if ($iKeyIterations<=0) return null;
    if (!array_key_exists($sEncodingAlgorithm, self::ENCODING_ALGORITHMS)) return null;

    // Payload
    $sPayload = $this->decode(substr($sKey, $i+1), $sEncodingAlgorithm);
    if ($sPayload===false) return null;

    // Done
    return array(
      'key' => $sKeyAlgorithm,
      'iterations' => $iKeyIterations,
      'payload' => $sPayload,
    );
  }

  /**
   * {@inheritdoc}
   */
  public function keyVerify($sInput, $mKey, $sSalt=null, $bTimeInvariant=true)
  {
    $bUseRandomSalt = is_null($sSalt);
    $sKeyAlgorithm = $this->sKeyAlgorithm;
    $iKeyIterations = $this->iKeyIterations;
    if (is_array($mKey)) {
      // Raw (binary) input

      $sKey = $mKey['key'];
      $sSalt = $mKey['salt'];

    } else {
      // ASCII

      $mKey = $this->keyAscii2Binary($mKey, $sSalt);
      if (!is_array($mKey)) return $bTimeInvariant ? hash_equals('not', 'equal') : false;
      $sKeyAlgorithm = $mKey['header']['key'];
      $iKeyIterations = $mKey['header']['iterations'];
      $sKey = $mKey['payload']['key'];
      $sSalt = $mKey['payload']['salt'];

    }

    // Check key
    switch (self::KEY_ALGORITHMS[$sKeyAlgorithm][0]) {

    case 'PBKDF2':
      $sKey_input = hash_pbkdf2(
        self::KEY_ALGORITHMS[$sKeyAlgorithm][1],
        $sInput,
        $sSalt,
        $iKeyIterations,
        0,
        true
      );
      break;

    case null:
      $sKey_input = $sInput;
      break;

    }
    return $bTimeInvariant ? hash_equals($sKey, $sKey_input) : ($sKey==$sKey_input);
  }

  /**
   * {@inheritdoc}
   */
  public function mac($sInput, $bRaw=false)
  {
    switch (self::MAC_ALGORITHMS[$this->sMacAlgorithm][0]) {

    case 'HMAC':
      $sMac = hash_hmac(
        self::MAC_ALGORITHMS[$this->sMacAlgorithm][1],
        $sInput,
        substr($this->sMacKey, 0, self::MAC_ALGORITHMS[$this->sMacAlgorithm][3]),
        true
      );
      break;

    case null:
      $sMac = $sInput;
      break;

    }

    return
      $bRaw
      ? array('mac' => $sMac)
      : preg_replace(
        '/^\{([^:]+)(:-)+\}/',
        '{$1}',
        sprintf(
          '{%s:%s}%s',
          $this->sMacAlgorithm,
          $this->sEncodingAlgorithm,
          $this->encode($sMac)
        )
      );
  }

  /**
   * {@inheritdoc}
   */
  public function macHeader($sMac)
  {
    // Header
    $sMac = (string)$sMac;
    if ($sMac[0]!='{') return null;
    $i = strpos($sMac, '}');
    if ($i===false) return null;
    $sHeader = substr($sMac, 1, $i-1);
    $sEncodingAlgorithm = '-';
    $j = strpos($sHeader, ':');
    if ($j===false) {
      $sMacAlgorithm = $sHeader;
    } else {
      $sMacAlgorithm = substr($sHeader, 0, $j);
      $sEncodingAlgorithm = (string)substr($sHeader, $j+1);  // NB: index overflow leads to (boolean)false
    }

    // Check algorithms
    if (!array_key_exists($sMacAlgorithm, self::MAC_ALGORITHMS)) return null;
    if (!array_key_exists($sEncodingAlgorithm, self::ENCODING_ALGORITHMS)) return null;

    // Payload
    $sPayload = $this->decode(substr($sMac, $i+1), $sEncodingAlgorithm);
    if ($sPayload===false) return null;

    // Done
    return array(
      'mac' => $sMacAlgorithm,
      'payload' => $sPayload,
    );
  }

  /**
   * {@inheritdoc}
   */
  public function macVerify($sInput, $mMac, $bTimeInvariant=true)
  {
    $sMacAlgorithm = $this->sMacAlgorithm;
    if (is_array($mMac)) {
      // Raw (binary) input

      $sMac = $mMac['mac'];

    } else {
      // ASCII

      $mMac = $this->macAscii2Binary($mMac);
      if (!is_array($mMac)) return $bTimeInvariant ? hash_equals('not', 'equal') : false;
      $sMacAlgorithm = $mMac['header']['mac'];
      $sMac = $mMac['payload']['mac'];

    }

    // Check MAC
    switch (self::MAC_ALGORITHMS[$sMacAlgorithm][0]) {

    case 'HMAC':
      $sMac_input = hash_hmac(
        self::MAC_ALGORITHMS[$sMacAlgorithm][1],
        $sInput,
        substr($this->sMacKey, 0, self::MAC_ALGORITHMS[$sMacAlgorithm][3]),
        true
      );
      break;

    case null:
      $sMac_input = $sInput;
      break;

    }
    return $bTimeInvariant ? hash_equals($sMac, $sMac_input) : ($sMac==$sMac_input);
  }

  /**
   * {@inheritdoc}
   */
  public function encipher($sInput, $bRaw=false)
  {
    // Encipher

    // ... IV
    $sIv = null;
    if ($this->sCipherAlgorithm!='-') {
      $sIv = openssl_random_pseudo_bytes(self::CIPHER_ALGORITHMS[$this->sCipherAlgorithm][2]);
      $sCipher = openssl_encrypt(
        $sInput,
        self::CIPHER_ALGORITHMS[$this->sCipherAlgorithm][0],
        substr($this->sCipherKey, 0, self::CIPHER_ALGORITHMS[$this->sCipherAlgorithm][3]),
        OPENSSL_RAW_DATA,
        $sIv
      );
    } else {
      $sCipher = $sInput;
    }

    // ... MAC
    $sMac = null;
    if ($this->sMacAlgorithm!='-') {
      $sMac = hash_hmac(
        self::MAC_ALGORITHMS[$this->sMacAlgorithm][1],
        $sCipher.$sIv,
        substr($this->sMacKey, 0, self::MAC_ALGORITHMS[$this->sMacAlgorithm][3]),
        true
      );
    }

    // ... input
    return
      $bRaw
      ? array('cipher' => $sCipher, 'iv' => $sIv, 'mac' => $sMac)
      : preg_replace(
        '/^\{([^:]+)(:-)+\}/',
        '{$1}',
        sprintf(
          '{%s:%s:%s}%s',
          $this->sCipherAlgorithm,
          $this->sMacAlgorithm,
          $this->sEncodingAlgorithm,
          $this->encode($sCipher.$sIv.$sMac)
        )
      );
  }

  /**
   * {@inheritdoc}
   */
  public function cipherHeader($sCipher)
  {
    // Header
    $sCipher = (string)$sCipher;
    if ($sCipher[0]!='{') return null;
    $i = strpos($sCipher, '}');
    if ($i===false) return null;
    $sHeader = substr($sCipher, 1, $i-1);
    $sMacAlgorithm = '-';
    $sEncodingAlgorithm = '-';
    $j = strpos($sHeader, ':');
    if ($j===false) {
      $sCipherAlgorithm = $sHeader;
    } else {
      $sCipherAlgorithm = substr($sHeader, 0, $j);
      $sHeader = (string)substr($sHeader, $j+1);  // NB: index overflow leads to (boolean)false
      $k = strpos($sHeader, ':');
      if ($k===false) {
        $sMacAlgorithm = $sHeader;
      } else {
        $sMacAlgorithm = substr($sHeader, 0, $k);
        $sEncodingAlgorithm = (string)substr($sHeader, $k+1);  // NB: index overflow leads to (boolean)false
      }
    }

    // Check algorithms
    if (!array_key_exists($sCipherAlgorithm, self::CIPHER_ALGORITHMS)) return null;
    if (!array_key_exists($sMacAlgorithm, self::MAC_ALGORITHMS)) return null;
    if (!array_key_exists($sEncodingAlgorithm, self::ENCODING_ALGORITHMS)) return null;

    // Payload
    $sPayload = $this->decode(substr($sCipher, $i+1), $sEncodingAlgorithm);
    if ($sPayload===false) return null;

    // Done
    return array(
      'cipher' => $sCipherAlgorithm,
      'mac' => $sMacAlgorithm,
      'payload' => $sPayload,
    );
  }

  /**
   * {@inheritdoc}
   */
  public function decipher($mCipher, $bTimeInvariant=true)
  {
    $sCipherAlgorithm = $this->sCipherAlgorithm;
    $sMacAlgorithm = $this->sMacAlgorithm;
    if (is_array($mCipher)) {
      // Raw (binary) input

      $sCipher = $mCipher['cipher'];
      $sIv = $mCipher['iv'];
      $sMac = $mCipher['mac'];

    } else {
      // ASCII

      $mCipher = $this->cipherAscii2Binary($mCipher);
      if (!is_array($mCipher)) return $bTimeInvariant ? hash_equals('not', 'equal') : false;
      $sCipherAlgorithm = $mCipher['header']['cipher'];
      $sMacAlgorithm = $mCipher['header']['mac'];
      $sCipher = $mCipher['payload']['cipher'];
      $sIv = $mCipher['payload']['iv'];
      $sMac = $mCipher['payload']['mac'];

    }

    // Check MAC
    if ($sMacAlgorithm!='-') {
      $sMac_payload = hash_hmac(
        self::MAC_ALGORITHMS[$sMacAlgorithm][1],
        $sCipher.$sIv,
        substr($this->sMacKey, 0, self::MAC_ALGORITHMS[$sMacAlgorithm][3]),
        true
      );
      if ($bTimeInvariant ? !hash_equals($sMac, $sMac_payload) : ($sMac!=$sMac_payload)) {
        self::_warning('Invalid input (bad MAC) [BAD_MAC]', $this->bStrict);
        return null;
      }
    }

    // Decipher
    if ($sCipherAlgorithm!='-') {
      return openssl_decrypt(
        $sCipher,
        self::CIPHER_ALGORITHMS[$sCipherAlgorithm][0],
        substr($this->sCipherKey, 0, self::CIPHER_ALGORITHMS[$sCipherAlgorithm][3]),
        OPENSSL_RAW_DATA,
        $sIv
      );
    } else {
      return $sCipher;
    }
  }

}
