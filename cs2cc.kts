#!/usr/bin/env kscript
@file:DependsOn("se.bjurr.violations:violations-lib:1.155.3")

import se.bjurr.violations.lib.ViolationsApi.violationsApi
import se.bjurr.violations.lib.model.Violation
import se.bjurr.violations.lib.reports.Parser
import se.bjurr.violations.violationslib.com.google.gson.JsonArray
import se.bjurr.violations.violationslib.com.google.gson.JsonObject
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest
import java.util.stream.Stream
import kotlin.system.exitProcess

fun printUsage() {
    println("Usage: cs2cc <checkstyle xml regex> <android lint xml regex>")
    println("\tExample: cs2cc '.*detekt\\.xml$' '.*lint-results\\.xml$'")
    exitProcess(1)
}

val checkstylePattern = args.getOrNull(0)
if (checkstylePattern == null) printUsage()

val androidLintPattern = args.getOrNull(1)
if (androidLintPattern == null) printUsage()

val checkstyleViolations: List<Violation> = violationsApi()
        .withPattern(checkstylePattern)
        .inFolder(".")
        .findAll(Parser.CHECKSTYLE)
        .violations()
        .toList()

val androidLintViolations: List<Violation> = violationsApi()
    .withPattern(androidLintPattern)
    .inFolder(".")
    .findAll(Parser.ANDROIDLINT)
    .violations()
    .toList()

val cwd: Path = Paths.get("").toAbsolutePath()

val result = JsonArray()

(checkstyleViolations + androidLintViolations).forEach { violation ->
    val path = Paths.get(violation.file)
    var lines: Stream<String>? = null
    val contents = try {
        lines = Files.lines(path)
        lines.skip((violation.startLine - 1).toLong()).findFirst().orElse("")
    } catch (e: Throwable) {
        ""
    } finally {
        lines?.close()
    }
    val digest = MessageDigest.getInstance("MD5").apply {
        update(violation.file.toByteArray())
        update(contents.toByteArray())
        update(violation.message.toByteArray())
        update(violation.category.toByteArray())
        update(violation.group.toByteArray())
        update(violation.severity.name.toByteArray())
    }.digest()

    result.add(JsonObject().apply {
        addProperty("description", violation.message)
        addProperty("fingerprint", BigInteger(1, digest).toString(16).padStart(32, '0'))
        add("location", JsonObject().apply {
            addProperty("path", cwd.relativize(path).toString())
            add("lines", JsonObject().apply {
                addProperty("begin", violation.startLine)
            })
        })
    })
}

println(result.toString())

