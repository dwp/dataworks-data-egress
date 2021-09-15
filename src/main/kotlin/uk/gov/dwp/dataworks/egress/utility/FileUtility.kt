package uk.gov.dwp.dataworks.egress.utility

import uk.gov.dwp.dataworks.logging.DataworksLogger
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

object FileUtility {

    fun writeToFile(fileName: String, folder: String, targetContents: ByteArray) {
        val parent = File(if (folder.startsWith("/")) folder else "/$folder")

        if (!parent.isDirectory) {
            logger.info("Making parent directory", "parent" to "$parent", "filename" to fileName)
            if (!parent.mkdirs()) {
                logger.error("Failed to make parent directories", "parent" to "$parent", "filename" to fileName)
                throw RuntimeException("Failed to make parent directories, parent: '$parent', filename: '$fileName'")
            }
        }

        val file = File(parent, fileName)
        logger.info("Writing file", "file" to "$file", "parent" to "$parent", "filename" to fileName)
        file.writeBytes(targetContents)
    }

    fun timestampedFilename(original: String): String =
        if (extensionRe.containsMatchIn(original)) original.replace(extensionRe, ".$timestamp$1")
        else "$original.$timestamp"

    private val timestamp: String get() = SimpleDateFormat("YYYYMMdd").format(Date())
    private val extensionRe get() = Regex("""((\.[^.]{1,3})+)$""")
    private val logger = DataworksLogger.getLogger(FileUtility::class)

}
