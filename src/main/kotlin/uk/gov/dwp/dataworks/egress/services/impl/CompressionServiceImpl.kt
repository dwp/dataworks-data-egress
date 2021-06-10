package uk.gov.dwp.dataworks.egress.services.impl

import org.springframework.stereotype.Service
import uk.gov.dwp.dataworks.egress.services.CompressionService
import java.io.ByteArrayOutputStream
import java.util.zip.Deflater
import java.util.zip.GZIPOutputStream

@Service
class CompressionServiceImpl: CompressionService {
    override fun compress(format: String?, input: ByteArray): ByteArray =
        when (format) {
            "gz" -> {
                val outputStream = ByteArrayOutputStream()
                GZIPOutputStream(outputStream).use { it.write(input) }
                outputStream.toByteArray()
            }
            "z" -> {
                with(Deflater()) {
                    setInput(input)
                    finish()
                    val output = ByteArray(input.size)
                    deflate(output)
                    output
                }
            }
            else -> input
        }
}
