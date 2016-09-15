<?php // -*- mode:php; tab-width:2; c-basic-offset:2; intent-tabs-mode:nil; -*- ex: set tabstop=2 expandtab:
// DataCryptographerBundle\Command\DataCryptographerUpdateCommand.php

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

namespace DataCryptographerBundle\Command;
use DataCryptographerBundle\DBAL\Types\HashStringType;
use DataCryptographerBundle\DBAL\Types\KeyHashStringType;
use DataCryptographerBundle\DBAL\Types\CipherStringType;
use DataCryptographerBundle\DBAL\Types\CipherTextType;

use Symfony\Bundle\FrameworkBundle\Command\ContainerAwareCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/** Update cryptographer-related entities
 */
class DataCryptographerUpdateCommand
extends ContainerAwareCommand
{

  /*
   * METHODS: ContainerAwareCommand
   ********************************************************************************/

  protected function configure()
  {
    $this
      ->setName('datacryptographer:update')
      ->setDescription('Update the DataCryptographer-related fields of the given entity')
      ->addArgument(
        'entity',
        InputArgument::REQUIRED,
        'Entity to update (<bundle-name>:<entity-name>)'
      )
      ->addOption(
        'encoding',
        null,
        InputOption::VALUE_REQUIRED,
        'Change the output encoding'
      )
      ->addOption(
        'dry-run',
        null,
        InputOption::VALUE_NONE,
        'Dry-run; check which of the entity fields will be updated'
      )
      ->addOption(
        'I-DO-have-a-backup',
        null,
        InputOption::VALUE_NONE,
        'Shamelessly bail out unless you truly know what you\'re doing'
      )
      ;
  }

  protected function execute(InputInterface $oInputInterface, OutputInterface $oOutputInterface)
  {
    // Resources
    $oContainer = $this->getContainer();

    // Input

    // ... entity
    $sEntity = $oInputInterface->getArgument('entity');

    // Resources (cont'd)
    $oEntityManager = $oContainer->get('doctrine')->getManagerForClass($sEntity);

    // Retrieve DataCryptographer-related fields
    $oClassMetadata = $oEntityManager->getClassMetadata($sEntity);
    $asFields = $oClassMetadata->getFieldNames();
    $asFields_cryptographer = array();
    foreach ($asFields as $sField) {
      $mTypeOfField = $oClassMetadata->getTypeOfField($sField);
      if (!is_object($mTypeOfField)) $mTypeOfField = \Doctrine\DBAL\Types\Type::getType($mTypeOfField);
      if (
        $mTypeOfField instanceof HashStringType or
        $mTypeOfField instanceof KeyHashStringType or
        $mTypeOfField instanceof CipherStringType or
        $mTypeOfField instanceof CipherTextType
      ) {
        $asFields_cryptographer[$sField] = array(
          $mTypeOfField,
          sprintf('get%s', $sField),  // getter
          sprintf('set%s', $sField),  // setter
        );
      }
    }

    // ... output
    $oOutputInterface->writeln('Cryptographer-related fields are:');
    $oOutputInterface->writeln(sprintf('  %s', $sEntity));
    foreach ($asFields_cryptographer as $sField => $aField) {
      $oOutputInterface->writeln(sprintf('    %s (%s)', $sField, get_class($aField[0])));
    }

    // Dry-run ?
    if ($oInputInterface->getOption('dry-run')) {
      return;
    }

    // Do you have a backup ?
    if (!$oInputInterface->getOption('I-DO-have-a-backup')) {
      $oOutputInterface->writeln('');
      $oOutputInterface->writeln('!!! WARNING !!! WARNING !!! WARNING !!! WARNING !!! WARNING !!! WARNING !!!');
      $oOutputInterface->writeln('');
      $oOutputInterface->writeln('                     BACKUP YOUR DATA BEFORE PROCDEEDING');
      $oOutputInterface->writeln('');
      $oOutputInterface->writeln('In case some misconfiguration or error affects the cryptographic operations,');
      $oOutputInterface->writeln('               YOUR DATA MAY BECOME IRREVERSIBLY IRRECOVERABLE');
      $oOutputInterface->writeln('');
      $oOutputInterface->writeln('!!! WARNING !!! WARNING !!! WARNING !!! WARNING !!! WARNING !!! WARNING !!!');
      return;
    }

    // Resources (cont'd)
    $oDataCryptographer = $oContainer->get('DataCryptographer');
    $sEncoding = $oInputInterface->getOption('encoding');
    if (!is_null($sEncoding)) $oDataCryptographer->changeEncoding($sEncoding);

    // Update fields
    $oOutputInterface->write('Updating entries');
    $oRepository = $oEntityManager->getRepository($sEntity);
    $i = 0;
    foreach (@$oRepository->findAll() as $oEntity) {
      $oOutputInterface->write('.');
      $i++;
      foreach ($asFields_cryptographer as $sField => $aField) {
        $mTypeOfField = $aField[0];
        $sField_get = $aField[1];
        $sField_set = $aField[2];
        $mValue = $oEntity->$sField_get();
        if (is_null($mValue)) continue;
        if ($mTypeOfField instanceof HashStringType) {
          if ($oDataCryptographer->hashHeader($mValue)) continue;
          $oEntity->$sField_set($oDataCryptographer->hash($mValue));
        } elseif ($mTypeOfField instanceof KeyHashStringType) {
          if ($oDataCryptographer->keyHeader($mValue)) continue;
          $oEntity->$sField_set($oDataCryptographer->key($mValue));
        } elseif ($mTypeOfField instanceof CipherStringType or $mTypeOfField instanceof CipherTextType) {
          if ($oDataCryptographer->cipherHeader($mValue)) continue; // this MAY happen if the configured password/salts do not match the data
          $oEntity->$sField_set($oDataCryptographer->encipher($mValue));
        }
        $oEntityManager->flush();
      }
    }
    $oOutputInterface->writeln('');
    $oOutputInterface->writeln(sprintf('  %d entries updated', $i));
  }

}
