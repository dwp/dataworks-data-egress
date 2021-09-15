package uk.gov.dwp.dataworks.egress.services.impl

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.FlowCollector
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.future.await
import org.springframework.stereotype.Service
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient
import software.amazon.awssdk.services.dynamodb.model.AttributeValue
import software.amazon.awssdk.services.dynamodb.model.ScanRequest
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification
import uk.gov.dwp.dataworks.egress.services.DbService
import java.text.SimpleDateFormat
import java.util.*

@Service
class DbServiceImpl(private val dynamoDb: DynamoDbAsyncClient,
                    private val dataEgressTable: String): DbService {

    override suspend fun tableEntryMatches(prefix: String): List<EgressSpecification> =
        entries().toList().flatten().filter { matchesSourcePrefix(it, prefix) }.map(::egressSpecification)

    private fun matchesSourcePrefix(it: Map<String, AttributeValue>,
                                    prefix: String) =
        it[SOURCE_PREFIX_COLUMN]?.s()
            ?.replace(TODAYS_DATE_PLACEHOLDER, todaysDate())
            ?.replace(Regex("""\*$"""), "")?.let(prefix::startsWith) ?: false

    private fun egressSpecification(dynamoDbRecord: Map<String, AttributeValue>) =
        EgressSpecification(
            sourceBucket = attributeStringValue(dynamoDbRecord, SOURCE_BUCKET_COLUMN),
            sourcePrefix = attributeStringValue(dynamoDbRecord, SOURCE_PREFIX_COLUMN).replace(TODAYS_DATE_PLACEHOLDER,
                todaysDate()).replace(Regex("""\*$"""), ""),
            destinationBucket = attributeStringValue(dynamoDbRecord, DESTINATION_BUCKET_COLUMN),
            destinationPrefix = attributeStringValue(dynamoDbRecord, DESTINATION_PREFIX_COLUMN).replace(TODAYS_DATE_PLACEHOLDER,
                todaysDate()).replace(TODAYS_YYYYMMDD_FORMATTED_DATE_PLACEHOLDER, todaysDate("yyyyMMdd")),
            transferType = attributeStringValue(dynamoDbRecord, TRANSFER_TYPE_COLUMN),
            decrypt = dynamoDbRecord[DECRYPT_COLUMN]?.bool() ?: false,
            rewrapDataKey = dynamoDbRecord[REWRAP_DATAKEY_COLUMN]?.bool() ?: false,
            encryptingKeySsmParmName = dynamoDbRecord[ENCRYPTING_KEY_SSM_PARAM_NAME_COLUMN]?.s(),
            compress = dynamoDbRecord[COMPRESS_COLUMN]?.bool() ?: false,
            compressionFormat = dynamoDbRecord[COMPRESSION_FORMAT_COLUMN]?.s(),
            roleArn = dynamoDbRecord[ROLE_ARN_COLUMN]?.s(),
            pipelineName = attributeStringValue(dynamoDbRecord, PIPELINE_COLUMN),
            recipient = attributeStringValue(dynamoDbRecord, RECIPIENT_COLUMN),
            controlFilePrefix = dynamoDbRecord[CONTROL_FILE_PREFIX_COLUMN]?.s(),
            timestampOutput = dynamoDbRecord[TIMESTAMP_OUTPUT_COLUMN]?.bool() ?: false
        )

    private suspend fun entries(): Flow<List<Map<String, AttributeValue>>> =
        flow { entriesEmitter(this) }

    private tailrec suspend fun entriesEmitter(collector: FlowCollector<List<Map<String, AttributeValue>>>, startKey: Map<String, AttributeValue>? = null) {
        val response = dynamoDb.scan(scanRequest(startKey)).await()
        val nextPage = response.items()
        val lastKey = response.lastEvaluatedKey()

        collector.emit(nextPage)

        if (lastKey != null && lastKey.isNotEmpty()) {
            entriesEmitter(collector, lastKey)
        }
    }

    private fun scanRequest(startKey: Map<String, AttributeValue>?): ScanRequest =
        with(ScanRequest.builder()) {
            tableName(dataEgressTable)
            startKey?.let {
                exclusiveStartKey(startKey)
            }
            build()
        }

    private fun attributeStringValue(it: Map<String, AttributeValue>, key: String) = it[key]?.s() ?: ""
    private fun todaysDate(dateFormat:String = "yyyy-MM-dd") = SimpleDateFormat(dateFormat).format(Date())

    companion object {
        private const val SOURCE_PREFIX_COLUMN: String = "source_prefix"
        private const val SOURCE_BUCKET_COLUMN: String = "source_bucket"
        private const val DESTINATION_BUCKET_COLUMN: String = "destination_bucket"
        private const val DESTINATION_PREFIX_COLUMN: String = "destination_prefix"
        private const val TRANSFER_TYPE_COLUMN: String = "transfer_type"
        private const val COMPRESS_COLUMN: String = "compress"
        private const val DECRYPT_COLUMN: String = "decrypt"
        private const val REWRAP_DATAKEY_COLUMN: String = "rewrap_datakey"
        private const val ENCRYPTING_KEY_SSM_PARAM_NAME_COLUMN: String = "encrypting_key_ssm_parm_name"
        private const val COMPRESSION_FORMAT_COLUMN: String = "compress_fmt"
        private const val ROLE_ARN_COLUMN: String = "role_arn"
        private const val CONTROL_FILE_PREFIX_COLUMN: String = "control_file_prefix"
        private const val TIMESTAMP_OUTPUT_COLUMN: String = "timestamp_files"
        private const val TODAYS_DATE_PLACEHOLDER = "\$TODAYS_DATE"
        private const val TODAYS_YYYYMMDD_FORMATTED_DATE_PLACEHOLDER = "\$TODAYS_YYYYMMDD_FORMATTED_DATE"
        private const val PIPELINE_COLUMN = "pipeline_name"
        private const val RECIPIENT_COLUMN = "recipient_name"
    }
}
