package uk.gov.dwp.dataworks.egress.utility

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import uk.gov.dwp.dataworks.egress.utility.FileUtility.timestampedFilename
import java.text.SimpleDateFormat
import java.util.*

class FilenameUtilityTest: StringSpec() {

    init {
        "It should insert timestamp before extension" {
            val original = "directory/filename.ex1"
            timestampedFilename(original) shouldBe """directory/filename.${timestamp}.ex1"""
        }

        "It should insert timestamp before all extensions" {
            val original = "directory/filename.ex1.ex2"
            timestampedFilename(original) shouldBe """directory/filename.${timestamp}.ex1.ex2"""
        }

        "It should insert timestamp before after filename parts" {
            val original = "directory/filename1.filename2.ex1.ex2"
            timestampedFilename(original) shouldBe """directory/filename1.filename2.${timestamp}.ex1.ex2"""
        }

        "It should insert timestamp at the end if no extension" {
            val original = "directory/filename"
            timestampedFilename(original) shouldBe """directory/filename.${timestamp}"""
        }
    }

    val timestamp: String = SimpleDateFormat("YYYYMMdd").format(Date())

}
