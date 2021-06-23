package uk.gov.dwp.dataworks.egress.services

interface PushGatewayService {
    fun pushMetrics()
    fun pushFinalMetrics()
    fun deleteMetrics()
}
