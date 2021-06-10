import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
	id( "com.github.ben-manes.versions") version "0.39.0"
	id("io.spring.dependency-management") version "1.0.11.RELEASE"
	id("org.springframework.boot") version "2.4.3"
	kotlin("jvm") version "1.5.10"
	kotlin("plugin.spring") version "1.5.10"
}

group = "uk.gov.dwp.dataworks"
version = "0.0.1-SNAPSHOT"
java.sourceCompatibility = JavaVersion.VERSION_11

repositories {
	mavenCentral()
	maven(url = "https://jitpack.io")
}

dependencies {
	annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

	implementation("com.amazonaws:aws-java-sdk-s3:1.12.3")
	implementation("com.github.dwp:dataworks-common-logging:0.0.6")
	implementation("com.google.code.gson:gson:2.8.7")
	implementation("org.bouncycastle:bcprov-ext-jdk15on:1.69")

	implementation("org.jetbrains.kotlin:kotlin-reflect")
	implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
	implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.5.0")
	implementation("org.jetbrains.kotlinx:kotlinx-coroutines-jdk8:1.5.0")

	implementation("org.springframework.boot:spring-boot-starter")
	implementation("org.springframework.boot:spring-boot-starter-cache")
	implementation("org.springframework.retry:spring-retry")

	implementation(platform("software.amazon.awssdk:bom:2.16.81"))
	implementation("software.amazon.awssdk:dynamodb")
	implementation("software.amazon.awssdk:sqs")
	implementation("software.amazon.awssdk:sts")
	implementation("software.amazon.awssdk:s3")

	testImplementation("com.nhaarman.mockitokotlin2:mockito-kotlin:2.2.0")
	testImplementation("io.kotest:kotest-assertions-core-jvm:4.6.0")
	testImplementation("io.kotest:kotest-assertions-json-jvm:4.6.0")
	testImplementation("io.kotest:kotest-property-jvm:4.6.0")
	testImplementation("io.kotest:kotest-runner-junit5-jvm:4.6.0")
	testImplementation("io.kotest:kotest-extensions-spring:4.4.3")
	testImplementation("org.springframework.boot:spring-boot-starter-test") {
		exclude(group = "org.junit.vintage", module = "junit-vintage-engine")
	}
}

tasks.withType<KotlinCompile> {
	kotlinOptions {
		freeCompilerArgs = listOf("-Xjsr305=strict")
		jvmTarget = "11"
	}
}

sourceSets {
	create("integration") {
		java.srcDir(file("src/integration/kotlin"))
		compileClasspath += sourceSets.getByName("main").output + configurations.testRuntimeClasspath
		runtimeClasspath += output + compileClasspath
	}
}

tasks.register<Test>("integration") {
	description = "Runs the integration tests"
	group = "verification"
	testClassesDirs = sourceSets["integration"].output.classesDirs
	classpath = sourceSets["integration"].runtimeClasspath
	useJUnitPlatform()
	testLogging {
		exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
		events = setOf(org.gradle.api.tasks.testing.logging.TestLogEvent.SKIPPED, org.gradle.api.tasks.testing.logging.TestLogEvent.PASSED, org.gradle.api.tasks.testing.logging.TestLogEvent.FAILED, org.gradle.api.tasks.testing.logging.TestLogEvent.STANDARD_OUT)
	}
}

tasks.withType<Test> {
	useJUnitPlatform()
}
