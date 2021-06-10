package uk.gov.dwp.dataworks.egress.configuration

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import java.security.SecureRandom

@Configuration
class ContextConfiguration {

    @Bean
    @Profile("strongRng")
    fun secureRandom(): SecureRandom = SecureRandom.getInstanceStrong()

    @Bean
    @Profile("!strongRng")
    fun psuedoRandom(): SecureRandom = SecureRandom.getInstance("SHA1PRNG")
}
