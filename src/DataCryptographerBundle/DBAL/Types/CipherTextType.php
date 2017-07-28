<?php // -*- mode:php; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
// DataCryptographerBundle\DBAL\Types\CipherTextType.php

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
 * @subpackage DoctrineExtension
 * @copyright  2016 Idiap Research Institute <http://www.idiap.ch>
 * @author     Cedric Dufour <http://cedric.dufour.name>
 * @license    http://www.gnu.org/licenses/gpl-3.0.html GNU General Public License (GPL) Version 3
 * @version    %{VERSION}
 * @link       https://github.com/idiap/symfony-bundle-datacryptographer
 */

namespace DataCryptographerBundle\DBAL\Types;
use DataCryptographerBundle\DataCryptographerInterface;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\TextType;

/** Cipher (encrypted) text type [cipher_text]
 *
 * <P>This class extends the default <SAMP>text</SAMP> type in such a way
 * to encipher/decipher (encrypt/decrypt) the data being stored/recovered
 * to/from the database.</P>
 * <P>In order to use this data type in your application, the following
 * declaration MUST be added to your configuration:</P>
 * <CODE>
 * doctrine:
 *   dbal:
 *     types:
 *       cipher_text: 'DataCryptographerBundle\DBAL\Types\CipherTextType'
 * </CODE>
 *
 * @package    DataCryptographerBundle
 * @subpackage DoctrineExtension
 */
class CipherTextType
  extends TextType
{

  /*
   * PROPERTIES
   ********************************************************************************/

  /** Data cryptographer
   * @var DataCryptographerInterface
   */
  protected static $oDataCryptographer;


  /*
   * METHODS
   ********************************************************************************/

  public static function setCryptographer(DataCryptographerInterface $oDataCryptographer)
  {
    static::$oDataCryptographer = $oDataCryptographer;
  }


  /*
   * METHODS: TextType
   ********************************************************************************/

  public function convertToPHPValue($mValue, AbstractPlatform $oPlatform)
  {
    $mValue = parent::convertToPHPValue($mValue, $oPlatform);
    $mValue_deciphered = !is_null($mValue) ? static::$oDataCryptographer->decipher($mValue) : null;
    return !is_null($mValue_deciphered) ? $mValue_deciphered : $mValue;
  }

  public function convertToDatabaseValue($mValue, AbstractPlatform $oPlatform)
  {
    if (!is_null($mValue) and !static::$oDataCryptographer->cipherHeader($mValue)) $mValue = static::$oDataCryptographer->encipher($mValue);
    return parent::convertToDatabaseValue($mValue, $oPlatform);
  }

  public function getName()
  {
    return 'cipher_text';
  }

}
