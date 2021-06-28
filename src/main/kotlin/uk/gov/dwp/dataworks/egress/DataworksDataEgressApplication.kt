package uk.gov.dwp.dataworks.egress

import io.prometheus.client.spring.web.EnablePrometheusTiming
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.runBlocking
import org.springframework.boot.CommandLineRunner
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.scheduling.annotation.EnableScheduling
import uk.gov.dwp.dataworks.egress.domain.EgressSpecification
import uk.gov.dwp.dataworks.egress.services.*
import uk.gov.dwp.dataworks.logging.DataworksLogger
import java.util.concurrent.atomic.AtomicBoolean

@SpringBootApplication
@EnableScheduling
@EnablePrometheusTiming
class DataworksDataEgressApplication(
    private val queueService: QueueService,
    private val dbService: DbService,
    private val dataService: DataService
) : CommandLineRunner {

    override fun run(vararg args: String?) {
        runBlocking {
            while (proceed.get()) {
                try {
                    queueService.incomingPrefixes()
                        .map { (receipt, prefixes) ->
                            Pair(
                                receipt,
                                prefixes.flatMap { dbService.tableEntryMatches(it) })
                        }
                        .map { (receiptHandle, egressRequests) -> Pair(receiptHandle, egressObjects(egressRequests)) }
                        .filter { it.second }.map { it.first }
                        .map(queueService::deleteMessage)
                        .collect {
                            logger.info("Message processed")
                        }


                } catch (e: Throwable) {
                    logger.error("Error in flow", e)
                }
            }
        }
    }

    private suspend fun egressObjects(requests: List<EgressSpecification>): Boolean =
        requests.map { specification -> dataService.egressObjects(specification) }.all { it }

    companion object {
        private val logger = DataworksLogger.getLogger(DataworksDataEgressApplication::class)
        private val proceed = AtomicBoolean(true)
    }
}

fun main(args: Array<String>) {
    runApplication<DataworksDataEgressApplication>(*args)
}
