import se.bjurr.violations.lib.ViolationsApi.violationsApi
import se.bjurr.violations.lib.model.Violation
import se.bjurr.violations.lib.reports.Parser
import se.bjurr.violations.violationslib.com.google.gson.JsonArray
import se.bjurr.violations.violationslib.com.google.gson.JsonObject
import java.math.BigInteger
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest
import kotlin.system.exitProcess

//DEPS se.bjurr.violations:violations-lib:1.96

val pattern = args.getOrNull(0)
if (pattern == null) {
    println("You must specify a regex pattern to find checkstyle xml files.")
    exitProcess(1)
}

val violations: List<Violation> = violationsApi()
        .withPattern(pattern)
        .inFolder(".")
        .findAll(Parser.CHECKSTYLE)
        .violations()

val pwd: Path = Paths.get("").toAbsolutePath()

val result = JsonArray()

violations.forEach { violation ->
    val relativePath = pwd.relativize(Paths.get(violation.file))
    val digest = MessageDigest.getInstance("MD5").apply {
        update(violation.file.toByteArray())
        update(violation.startLine.toByte())
        update(violation.endLine.toByte())
        update(violation.message.toByteArray())
        update(violation.category.toByteArray())
        update(violation.group.toByteArray())
        update(violation.severity.name.toByteArray())
    }.digest()

    result.add(JsonObject().apply {
        addProperty("description", violation.message)
        addProperty("fingerprint", BigInteger(1, digest).toString(16).padStart(32, '0'))
        add("location", JsonObject().apply {
            addProperty("path", relativePath.toString())
            add("lines", JsonObject().apply {
                addProperty("begin", violation.startLine)
            })
        })
    })
}

println(result.toString())

