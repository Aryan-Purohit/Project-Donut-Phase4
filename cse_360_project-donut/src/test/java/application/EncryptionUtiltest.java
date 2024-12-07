package application;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;


import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionUtiltest {

    private static final String TEST_PASSWORD_KEY_FILE = "testPasswordKey.key";
    private static final String TEST_ARTICLE_KEY_FILE = "testArticleKey.key";

    @AfterEach
    void tearDown() {
        // Clean up test files
        new File(TEST_PASSWORD_KEY_FILE).delete();
        new File(TEST_ARTICLE_KEY_FILE).delete();
    }

    @Test
    void testEncryptAndDecrypt() throws Exception {
        String plainText = "TestEncryption";
        byte[] key = EncryptionUtil.generateAndStoreKey(TEST_PASSWORD_KEY_FILE);

        byte[] encrypted = EncryptionUtil.encrypt(plainText, key);
        assertNotNull(encrypted, "Encrypted value should not be null");

        String decrypted = EncryptionUtil.decrypt(encrypted, key);
        assertEquals(plainText, decrypted, "Decrypted value should match the original plain text");
    }

    @Test
    void testGenerateAndStoreKey() throws IOException {
        byte[] key = EncryptionUtil.generateAndStoreKey(TEST_PASSWORD_KEY_FILE);
        assertNotNull(key, "Generated key should not be null");
        assertEquals(16, key.length, "Generated key should be 16 bytes for AES-128");

        File keyFile = new File(TEST_PASSWORD_KEY_FILE);
        assertTrue(keyFile.exists(), "Key file should exist after generation");

        byte[] loadedKey = EncryptionUtil.loadKey(TEST_PASSWORD_KEY_FILE);
        assertArrayEquals(key, loadedKey, "Loaded key should match the generated key");
    }

    @Test
    void testLoadKeyCreatesNewKeyIfNotExists() throws IOException {
        File keyFile = new File(TEST_ARTICLE_KEY_FILE);
        assertFalse(keyFile.exists(), "Key file should not exist initially");

        byte[] key = EncryptionUtil.loadKey(TEST_ARTICLE_KEY_FILE);
        assertNotNull(key, "Key should be generated and loaded");
        assertEquals(16, key.length, "Generated key should be 16 bytes");

        assertTrue(keyFile.exists(), "Key file should be created");
    }

    @Test
    void testLoadKeyLoadsExistingKey() throws IOException {
        byte[] generatedKey = EncryptionUtil.generateAndStoreKey(TEST_PASSWORD_KEY_FILE);
        byte[] loadedKey = EncryptionUtil.loadKey(TEST_PASSWORD_KEY_FILE);

        assertArrayEquals(generatedKey, loadedKey, "Loaded key should match the generated key");
    }

    @Test
    void testGetPasswordKey() throws IOException {
        byte[] key = EncryptionUtil.getPasswordKey();
        assertNotNull(key, "Password key should not be null");
        assertEquals(16, key.length, "Password key should be 16 bytes");

        File keyFile = new File(EncryptionUtil.getPasswordKeyFile());
        assertTrue(keyFile.exists(), "Password key file should exist");
    }

    @Test
    void testGetArticleKey() throws IOException {
        byte[] key = EncryptionUtil.getArticleKey();
        assertNotNull(key, "Article key should not be null");
        assertEquals(16, key.length, "Article key should be 16 bytes");

        File keyFile = new File(EncryptionUtil.getArticleKeyFile());
        assertTrue(keyFile.exists(), "Article key file should exist");
    }
}