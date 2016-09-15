<?php // -*- mode:php; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
// DataCryptographerBundle\DataCryptographerBundle.php

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
 * @subpackage SymfonyIntegration
 * @copyright  2016 Idiap Research Institute <http://www.idiap.ch>
 * @author     Cedric Dufour <http://cedric.dufour.name>
 * @license    http://www.gnu.org/licenses/gpl-3.0.html GNU General Public License (GPL) Version 3
 * @version    %{VERSION}
 * @link       https://github.com/idiap/symfony-bundle-datacryptographer
 */

namespace DataCryptographerBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;

/** Data cryptographer bundle
 * @package    DataCryptographerBundle
 * @subpackage SymfonyIntegration
 */
class DataCryptographerBundle extends Bundle
{
  public function boot()
  {
    // Associate data cryptographer with depending data types
    $oDataCryptographer = $this->container->get('DataCryptographer');
    \DataCryptographerBundle\DBAL\Types\HashStringType::setCryptographer($oDataCryptographer);
    \DataCryptographerBundle\DBAL\Types\KeyHashStringType::setCryptographer($oDataCryptographer);
    \DataCryptographerBundle\DBAL\Types\CipherStringType::setCryptographer($oDataCryptographer);
    \DataCryptographerBundle\DBAL\Types\CipherTextType::setCryptographer($oDataCryptographer);
  }
}
