<?php

/*
 * == dataLock Class ==
 * Lock data before saving it to the database.
 * 
 * ** !! To make it saver, encrypt this file with IonCube. !! **
 * 
 * Usage:
 * -------------
 * 1. To encrypt for the database:
 *      $encrypted = DataLock::ENCRYPT(What you want to encrypt);
 *      - You can save this to the database.
 * 
 * 2. To decrypt on the website:
 *      $decrypted = DataLock::DECRYPT(Encrypted string from the database);
 * 
 * Use varbinary(1000), 1000 at least, for the database column.
 */

interface DataLockModel {

    static function ENCRYPT($query);

    static function DECRYPT($query);
}

class DataLock implements dataLockModel {

    //Known variables.
    protected static $SALT = "hereyoursalt";
    protected static $METHOD = 'aes-256-cbc';

    //Encrypt the given data with available salt.
    static function ENCRYPT($notEncrypted = "") {
        return base64_encode(openssl_encrypt($notEncrypted, self::$METHOD, self::getSalt(), OPENSSL_RAW_DATA, self::getIV()));
    }

    //Decrypt the encrypted string.
    static function DECRYPT($encrypted = "") {
        return openssl_decrypt(base64_decode($encrypted), self::$METHOD, self::getSalt(), OPENSSL_RAW_DATA, self::getIV());
    }

    //Get the salt and hash it.
    private static function getSalt() {
        return substr(hash('sha256', self::$SALT, true), 0, 32);
    }

    //Get the IV.
    private static function getIV() {
        return chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);
    }

}
