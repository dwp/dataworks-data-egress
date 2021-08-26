package uk.gov.dwp.dataworks.egress.services.impl

import com.nhaarman.mockitokotlin2.*
import io.kotest.core.spec.style.WordSpec
import io.kotest.matchers.collections.shouldContainExactly
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient
import software.amazon.awssdk.services.dynamodb.model.AttributeValue
import software.amazon.awssdk.services.dynamodb.model.ScanRequest
import software.amazon.awssdk.services.dynamodb.model.ScanResponse
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.CompletableFuture

class DbServiceImplTest : WordSpec() {
    init {
        "DbService" should {

            "page for all items, returning matches, filtering non-matches" {
                val receivedPrefix = "source/prefix/pipeline_success.flag"
                val matchingPrefix = "source/prefix/"
                val matchingItem = egressTableItem(matchingPrefix)
                val nonMatchingItem = egressTableItem("non/matching/prefix")

                val scanResponse1 = with(ScanResponse.builder()) {
                    items(nonMatchingItem)
                    lastEvaluatedKey(mapOf(SOURCE_PREFIX_KEY to attributeValue(LAST_EVALUATED_KEY)))
                    build()
                }

                val scanResponse2 = with(ScanResponse.builder()) {
                    items(matchingItem)
                    build()
                }

                val scanFuture1 = CompletableFuture.completedFuture(scanResponse1)
                val scanFuture2 = CompletableFuture.completedFuture(scanResponse2)
                val dynamoDb = mock<DynamoDbAsyncClient> {
                    on { scan(any<ScanRequest>()) } doReturnConsecutively listOf(scanFuture1, scanFuture2)
                }
                val dbService = DbServiceImpl(dynamoDb, DATA_EGRESS_TABLE)
                val entries = dbService.tableEntryMatches(receivedPrefix)
                entries shouldContainExactly listOf(egressSpecification(matchingPrefix))
                verify(dynamoDb, times(2)).scan(any<ScanRequest>())
                verifyNoMoreInteractions(dynamoDb)
            }

            "match items with today's date" {
                val interpolatedPrefix = "source/prefix/${todaysDate()}"
                val receivedPrefix = "$interpolatedPrefix/pipeline_success.flag"
                val matchingPrefix = "source/prefix/$TODAYS_DATE_PLACEHOLDER/"

                val matchingItem = egressTableItem(matchingPrefix)
                val scanResponse = with(ScanResponse.builder()) {
                    items(matchingItem)
                    build()
                }
                val scanFuture = CompletableFuture.completedFuture(scanResponse)
                val dynamoDb = mock<DynamoDbAsyncClient> {
                    on { scan(any<ScanRequest>()) } doReturn scanFuture
                }
                val dbService = DbServiceImpl(dynamoDb, DATA_EGRESS_TABLE)
                val entries = dbService.tableEntryMatches(receivedPrefix)
                entries shouldContainExactly listOf(egressSpecification("$interpolatedPrefix/"))
            }

            "match items with wildcard" {
                val interpolatedPrefix = "source/prefix/${todaysDate()}"
                val receivedPrefix = "$interpolatedPrefix/pipeline_success.flag"
                val matchingPrefix = "source/prefix/$TODAYS_DATE_PLACEHOLDER/*"

                val matchingItem = egressTableItem(matchingPrefix)
                val scanResponse = with(ScanResponse.builder()) {
                    items(matchingItem)
                    build()
                }
                val scanFuture = CompletableFuture.completedFuture(scanResponse)
                val dynamoDb = mock<DynamoDbAsyncClient> {
                    on { scan(any<ScanRequest>()) } doReturn scanFuture
                }
                val dbService = DbServiceImpl(dynamoDb, DATA_EGRESS_TABLE)
                val entries = dbService.tableEntryMatches(receivedPrefix)
                entries shouldContainExactly listOf(egressSpecification("$interpolatedPrefix/"))
            }

            "match source prefix having date within path" {
                val interpolatedPrefix = "source/prefix/${todaysDate()}/collection"
                val receivedPrefix = "$interpolatedPrefix/pipeline_success.flag"
                val matchingPrefix = "source/prefix/$TODAYS_DATE_PLACEHOLDER/collection/"

                val matchingItem = egressTableItem(matchingPrefix)
                val scanResponse = with(ScanResponse.builder()) {
                    items(matchingItem)
                    build()
                }
                val scanFuture = CompletableFuture.completedFuture(scanResponse)
                val dynamoDb = mock<DynamoDbAsyncClient> {
                    on { scan(any<ScanRequest>()) } doReturn scanFuture
                }
                val dbService = DbServiceImpl(dynamoDb, DATA_EGRESS_TABLE)
                val entries = dbService.tableEntryMatches(receivedPrefix)
                entries shouldContainExactly listOf(egressSpecification("$interpolatedPrefix/"))
            }
            "match destination prefix with yyyyMMdd date format" {
                val interpolatedPrefix = "source/prefix/${todaysDate()}/collection"
                val receivedPrefix = "$interpolatedPrefix/pipeline_success.flag"
                val matchingSourcePrefix = "source/prefix/$TODAYS_DATE_PLACEHOLDER/collection/"
                val matchingDestinationPrefix = "destination/prefix/${todaysDate("yyyyMMdd")}"

                val matchingItem = egressTableItem(matchingSourcePrefix,DESTINATION_PREFIX+"/"+TODAYS_YYYYMMDD_FORMATTED_DATE_PLACEHOLDER)
                val scanResponse = with(ScanResponse.builder()) {
                    items(matchingItem)
                    build()
                }
                val scanFuture = CompletableFuture.completedFuture(scanResponse)
                val dynamoDb = mock<DynamoDbAsyncClient> {
                    on { scan(any<ScanRequest>()) } doReturn scanFuture
                }
                val dbService = DbServiceImpl(dynamoDb, DATA_EGRESS_TABLE)
                val entries = dbService.tableEntryMatches(receivedPrefix)
                entries shouldContainExactly listOf(egressSpecification("$interpolatedPrefix/","$matchingDestinationPrefix"))
            }
        }
    }

    private fun egressSpecification(sourcePrefix: String, destinationPrefix:String = DESTINATION_PREFIX) = EgressSpecification(
        SOURCE_BUCKET,
        sourcePrefix,
        DESTINATION_BUCKET,
        destinationPrefix,
        TRANSFER_TYPE,
        false,
        rewrapDataKey = REWRAP_DATAKEY,
        encryptingKeySsmParmName = ENCRYPTIING_KEY_SSM_PARAM_NAME,
        compress = false,
        compressionFormat = null,
        roleArn = null,
        pipelineName = PIPELINE_NAME,
        recipient = RECIPIENT


    )

    private fun egressTableItem(sourcePrefix: String, destinationPrefix: String = DESTINATION_PREFIX) = mapOf(
        SOURCE_PREFIX_KEY to attributeValue(sourcePrefix),
        DESTINATION_PREFIX_KEY to attributeValue(destinationPrefix),
        SOURCE_BUCKET_KEY to attributeValue(SOURCE_BUCKET),
        DESTINATION_BUCKET_KEY to attributeValue(DESTINATION_BUCKET),
        TRANSFER_TYPE_KEY to attributeValue(TRANSFER_TYPE),
        PIPELINE_NAME_KEY to attributeValue(PIPELINE_NAME),
        RECIPIENT_KEY to attributeValue(RECIPIENT),
        REWRAP_DATAKEY_KEY to attributeValue(REWRAP_DATAKEY.toString()),
        ENCRYPTIING_KEY_SSM_PARAM_NAME_KEY to attributeValue(ENCRYPTIING_KEY_SSM_PARAM_NAME)
    ).toMutableMap()


    companion object {
        private fun attributeValue(matchingPrefix: String) = AttributeValue.builder().s(matchingPrefix).build()
        private fun todaysDate(dateFormat:String ="yyyy-MM-dd") = SimpleDateFormat(dateFormat).format(Date())

        private const val DATA_EGRESS_TABLE = "DATA_EGRESS_TABLE"
        private const val SOURCE_PREFIX_KEY: String = "source_prefix"
        private const val SOURCE_BUCKET_KEY: String = "source_bucket"
        private const val DESTINATION_BUCKET_KEY: String = "destination_bucket"
        private const val DESTINATION_PREFIX_KEY: String = "destination_prefix"
        private const val TRANSFER_TYPE_KEY: String = "transfer_type"
        private const val TODAYS_YYYYMMDD_FORMATTED_DATE_PLACEHOLDER = "\$TODAYS_YYYYMMDD_FORMATTED_DATE"
        private const val TODAYS_DATE_PLACEHOLDER = "\$TODAYS_DATE"
        private const val PIPELINE_NAME_KEY = "pipeline_name"
        private const val RECIPIENT_KEY = "recipient_name"
        private const val REWRAP_DATAKEY_KEY: String = "rewrap_datakey"
        private const val ENCRYPTIING_KEY_SSM_PARAM_NAME_KEY: String = "encrypting_key_ssm_parm_name"

        private const val SOURCE_BUCKET = "source"
        private const val DESTINATION_BUCKET = "destination"
        private const val TRANSFER_TYPE = "S3"
        private const val DESTINATION_PREFIX = "destination/prefix"
        private const val LAST_EVALUATED_KEY = "LAST_EVALUATED_KEY"
        private const val PIPELINE_NAME = "pipeline"
        private const val RECIPIENT = "recipient"
        private const val REWRAP_DATAKEY = false
        private const val ENCRYPTIING_KEY_SSM_PARAM_NAME: String = "rtg_public"

    }
}
