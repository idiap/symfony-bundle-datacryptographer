<?php // -*- mode:php; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
// DataCryptographerBundle\DataCryptographerInterface.php

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

/** Cryptographer interface
 *
 * <P>This interface wraps the methods required to perform cryptographic operations on data.</P>
 *
 * @package    DataCryptographerBundle
 */
interface DataCryptographerInterface
{

  /*
   * METHODS
   ********************************************************************************/

  /** Returns the hash (digest/integrity code) for the given input
   *
   * <P>By default, this method returns the encoded payload ASCII <SAMP>string</SAMP>,
   * prefixed with the <SAMP>{HASH:ENCODING}</SAMP> identifiers of the algorithms
   * used to perform the hash and encoding.<BR/>
   * If raw (binary) output is requested, output will be as an <SAMP>array</SAMP> associating:</P>
   * <UL>
   * <LI><B>hash</B>: hash (digest/integrity code)</LI>
   * <LI><B>salt</B>: salt (for salted algorithms)</LI>
   * </UL>
   *
   * @param string $sInput Input to hash
   * @param boolean $bRaw Raw (binary) output
   * @return string|array Input hash
   */
  public function hash($sInput, $bRaw=false);

  /** Parses, validates and returns the given ASCII (headered/armored) hash components (algorithms and payload)
   *
   * <P>This method parses the given hash and looks for the <SAMP>{HASH:ENCODING}</SAMP>
   * identifiers of the algorithms used to perform the hash and encoding.<BR/>
   * On success, it returns an <B>array</B>, associating:</P>
   * <UL>
   * <LI><B>hash</B>: hash algorithm identifier</LI>
   * <LI><B>payload</B>: the decoded payload</LI>
   * </UL>
   * <P>Or <B>NULL</B> if no valid header can be found.</P>
   *
   * @param string $sHash ASCII (headered/armored) hash
   * @return array Hash components
   */
  public function hashHeader($sHash);

  /** Verifies the given input matches the given hash (digest/integrity code)
   *
   * <P>This method can use either the encoded payload ASCII <SAMP>string</SAMP>,
   * prefixed with the <SAMP>{HASH:ENCODING}</SAMP> identifiers of the algorithms
   * used to perform the hash and encoding<BR/>
   * OR a raw (binary) input <SAMP>array</SAMP>, associating:</P>
   * <UL>
   * <LI><B>hash</B>: hash (digest/integrity code)</LI>
   * <LI><B>salt</B>: salt (for salted algorithms)</LI>
   * </UL>
   *
   * @param string $sInput Input to verify
   * @param string|array $mHash Hash (digest/integrity code) to verify the input against to
   * @param boolean $bTimeInvariant Use time invariant comparison to mitigate timing attacks
   * @return boolean Input<->hash match
   */
  public function hashVerify($sInput, $mHash, $bTimeInvariant=true);

  /** Returns the derived key (or key hash) the given input
   *
   * <P>By default, this method returns the encoded payload ASCII <SAMP>string</SAMP>,
   * prefixed with the <SAMP>{KEY:ITERATIONS:ENCODING}</SAMP> identifiers of the algorithms
   * used to perform the key derivation and encoding.<BR/>
   * If raw (binary) output is requested, output will be as an <SAMP>array</SAMP> associating:</P>
   * <UL>
   * <LI><B>key</B>: (derived) key</LI>
   * <LI><B>salt</B>: salt (for salted algorithms)</LI>
   * </UL>
   * <P>If no key <B>salt</B> is given, a random salt will be generated and included in the
   * key payload, thus corresponding to a salted <B>key hash</B> rather than the derived key.</P>
   *
   * @param string $sInput Input to get the key derivation/hash from
   * @param string $sSalt Key salt
   * @param boolean $bRaw Raw (binary) output
   * @return string|array Input key
   */
  public function key($sInput, $sSalt=null, $bRaw=false);

  /** Parses, validates and returns the given ASCII (headered/armored) key components (algorithms and payload)
   *
   * <P>This method parses the given key and looks for the <SAMP>{KEY:ITERATIONS:ENCODING}</SAMP>
   * identifiers of the algorithms used to perform the key derivation and encoding.<BR/>
   * On success, it returns an <B>array</B>, associating:</P>
   * <UL>
   * <LI><B>key</B>: key algorithm identifier</LI>
   * <LI><B>payload</B>: the decoded payload</LI>
   * </UL>
   * <P>Or <B>NULL</B> if no valid header can be found.</P>
   *
   * @param string $sKey ASCII (headered/armored) key
   * @return array Key components
   */
  public function keyHeader($sKey);

  /** Verifies the given input matches the given derived key (or key hash)
   *
   * <P>This method can use either the encoded payload ASCII <SAMP>string</SAMP>,
   * prefixed with the <SAMP>{KEY:ITERATIONS:ENCODING}</SAMP> identifiers of the algorithms
   * used to perform the key derivation and encoding<BR/>
   * OR a raw (binary) input <SAMP>array</SAMP>, associating:</P>
   * <UL>
   * <LI><B>key</B>: (derived) key</LI>
   * <LI><B>salt</B>: salt (for salted algorithms)</LI>
   * </UL>
   *
   * @param string $sInput Input to verify
   * @param string|array $mKey Derived key (or key hash) to verify the input against to
   * @param string $sSalt Derived key salt
   * @param boolean $bTimeInvariant Use time invariant comparison to mitigate timing attacks
   * @return boolean Input<->key match
   */
  public function keyVerify($sInput, $mKey, $sSalt=null, $bTimeInvariant=true);

  /** Returns the MAC (authentication code) for the given input
   *
   * <P>By default, this method returns the encoded payload ASCII <SAMP>string</SAMP>,
   * prefixed with the <SAMP>{MAC:ENCODING}</SAMP> identifiers of the algorithms
   * used to perform the MAC and encoding.<BR/>
   * If raw (binary) output is requested, output will be as an <SAMP>array</SAMP> associating:</P>
   * <UL>
   * <LI><B>mac</B>: MAC (authentication code)</LI>
   * </UL>
   *
   * @param string $sInput Input to MAC
   * @param boolean $bRaw Raw (binary) output
   * @return string|array Input MAC
   */
  public function mac($sInput, $bRaw=false);

  /** Parses, validates and returns the given ASCII (headered/armored) MAC components (algorithms and payload)
   *
   * <P>This method parses the given MAC and looks for the <SAMP>{MAC:ENCODING}</SAMP>
   * identifiers of the algorithms used to perform the MAC and encoding.<BR/>
   * On success, it returns an <B>array</B>, associating:</P>
   * <UL>
   * <LI><B>mac</B>: MAC algorithm identifier</LI>
   * <LI><B>payload</B>: the decoded payload</LI>
   * </UL>
   * <P>Or <B>NULL</B> if no valid header can be found.</P>
   *
   * @param string $sMAC ASCII (headered/armored) MAC
   * @return array MAC components
   */
  public function macHeader($sMAC);

  /** Verifies the given input matches the given MAC (authentication code)
   *
   * <P>This method can use either the encoded payload ASCII <SAMP>string</SAMP>,
   * prefixed with the <SAMP>{MAC:ENCODING}</SAMP> identifiers of the algorithms
   * used to perform the MAC and encoding<BR/>
   * OR a raw (binary) input <SAMP>array</SAMP>, associating:</P>
   * <UL>
   * <LI><B>mac</B>: MAC (authentication code)</LI>
   * </UL>
   *
   * @param string $sInput Input to verify
   * @param string|array $mMAC MAC (authentication code) to verify the input against to
   * @param boolean $bTimeInvariant Use time invariant comparison to mitigate timing attacks
   * @return boolean Input<->MAC match
   */
  public function macVerify($sData, $mMAC, $bTimeInvariant=true);

  /** Returns the enciphered (encrypted) cipher for the given input
   *
   * <P>By default, this method returns the encoded payload ASCII <SAMP>string</SAMP>,
   * prefixed with the <SAMP>{CIPHER:MAC:ENCODING}</SAMP> identifiers of the algorithms
   * used to perform the encipherment and encoding.<BR/>
   * If raw (binary) output is requested, output will be as an <SAMP>array</SAMP> associating:</P>
   * <UL>
   * <LI><B>cipher</B>: cipher (encrypted input)</LI>
   * <LI><B>iv</B>: initialization vector (IV)</LI>
   * <LI><B>mac</B>: authentication code (MAC)</LI>
   * </UL>
   *
   * @param string $sInput Input to encipher
   * @param boolean $bRaw Raw (binary) output
   * @return string|array Cipher (enciphered/encrypted input)
   */
  public function encipher($sInput, $bRaw=false);

  /** Parses, validates and returns the given ASCII (headered/armored) cipher components (algorithms and payload)
   *
   * <P>This method parses the given cipher and looks for the <SAMP>{CIPHER:MAC:ENCODING}</SAMP>
   * identifiers of the algorithms used to perform the encipherment and encoding.<BR/>
   * On success, it returns an <B>array</B>, associating:</P>
   * <UL>
   * <LI><B>cipher</B>: cipher algorithm identifier</LI>
   * <LI><B>mac</B>: MAC algorithm identifier</LI>
   * <LI><B>payload</B>: the decoded payload</LI>
   * </UL>
   * <P>Or <B>NULL</B> if no valid header can be found.</P>
   *
   * @param string $sCipher ASCII (headered/armored) cipher
   * @return array Cipher components
   */
  public function cipherHeader($sCipher);

  /** Returns the deciphered (decrypted) cleartext for the given cipher
   *
   * <P>This method can use either the encoded payload ASCII <SAMP>string</SAMP>,
   * prefixed with the <SAMP>{CIPHER:MAC:ENCODING}</SAMP> identifiers of the algorithms
   * used to perform the encipherment and encoding<BR/>
   * OR a raw (binary) input <SAMP>array</SAMP>, associating:</P>
   * <UL>
   * <LI><B>cipher</B>: cipher (encrypted input)</LI>
   * <LI><B>iv</B>: initialization vector (IV)</LI>
   * <LI><B>mac</B>: authentication code (MAC)</LI>
   * </UL>
   *
   * @param string|array $mCipher Cipher (encrypted input) to decipher
   * @param boolean $bTimeInvariant Use time invariant MAC check to mitigate timing attacks
   * @return string Deciphered (decrypted) cleartext
   */
  public function decipher($mCipher, $bTimeInvariant=true);

}
