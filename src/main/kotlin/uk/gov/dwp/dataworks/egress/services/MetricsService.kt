package uk.gov.dwp.dataworks.egress.services

interface MetricsService {
    fun startMetricsEndpoint()
    fun stopMetricsEndpoint()
}
