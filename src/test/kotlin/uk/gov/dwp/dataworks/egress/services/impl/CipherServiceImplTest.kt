package uk.gov.dwp.dataworks.egress.services.impl

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import java.security.SecureRandom

class CipherServiceImplTest: StringSpec() {

    init {
        "Decrypting encrypted should give plaintext" {
            val cipherService = CipherServiceImpl(SecureRandom.getInstance("SHA1PRNG"), CIPHER_TRANSFORMATION)
            val original = "Original unencrypted text that should come out of decrypt".toByteArray()
            val (initialisationVector, encrypted) = cipherService.encrypt(DATA_KEY, original)
            val decrypted = cipherService.decrypt(DATA_KEY, initialisationVector, encrypted)
            decrypted shouldBe original
        }

        "Wrong key should give wrong plaintext" {
            val cipherService = CipherServiceImpl(SecureRandom.getInstance("SHA1PRNG"), CIPHER_TRANSFORMATION)
            val original = "Original unencrypted text that should come out of decrypt."
            val (initialisationVector, encrypted) = cipherService.encrypt(DATA_KEY, original.toByteArray())
            val decrypted = cipherService.decrypt(DATA_KEY.replace('c', 'd'), initialisationVector, encrypted)
            decrypted shouldNotBe original
        }

        "Wrong IV should give wrong plaintext" {
            val cipherService = CipherServiceImpl(SecureRandom.getInstance("SHA1PRNG"), CIPHER_TRANSFORMATION)
            val original = "Original unencrypted text that should come out of decrypt."
            val (initialisationVector, encrypted) = cipherService.encrypt(DATA_KEY, original.toByteArray())
            val firstChar = initialisationVector[0]
            val decrypted =
                cipherService.decrypt(DATA_KEY, initialisationVector.replace(firstChar, firstChar + 1), encrypted)
            decrypted shouldNotBe original
        }

    }

    companion object {
        private const val CIPHER_TRANSFORMATION = "AES/CTR/NoPadding"
        private const val DATA_KEY = "czMQLgW/OrzBZwFV9u4EBA=="
    }
}
