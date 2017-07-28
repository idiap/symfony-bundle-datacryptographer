<?php // -*- mode:php; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
// DataCryptographerBundle\DBAL\Types\HashStringType.php

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
use Doctrine\DBAL\Types\StringType;

/** Hash (digest) string type [hash_string]
 *
 * <P>This class extends the default <SAMP>string</SAMP> type in such a way
 * to have the data hash (digest/integrity code) stored/recovered to/from
 * the database.</P>
 * <P>In order to use this data type in your application, the following
 * declaration MUST be added to your configuration:</P>
 * <CODE>
 * doctrine:
 *   dbal:
 *     types:
 *       hash_string: 'DataCryptographerBundle\DBAL\Types\HashStringType'
 * </CODE>
 *
 * @package    DataCryptographerBundle
 * @subpackage DoctrineExtension
 */
class HashStringType
  extends StringType
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
   * METHODS: StringType
   ********************************************************************************/

  public function convertToDatabaseValue($mValue, AbstractPlatform $oPlatform)
  {
    if (!is_null($mValue) and !static::$oDataCryptographer->hashHeader($mValue)) $mValue = static::$oDataCryptographer->hash($mValue);
    return parent::convertToDatabaseValue($mValue, $oPlatform);
  }

  public function getName()
  {
    return 'hash_string';
  }

}
