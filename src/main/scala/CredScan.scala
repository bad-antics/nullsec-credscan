package nullsec.credscan

import scala.util.{Try, Success, Failure}
import scala.util.matching.Regex
import java.io.File
import java.nio.file.{Files, Paths, Path}
import scala.jdk.CollectionConverters._

/**
 * NullSec CredScan - Credential Scanner
 * 
 * Scala security tool demonstrating:
 * - Option types for null safety
 * - Either for error handling
 * - Case classes for immutable data
 * - Pattern matching for classification
 * - Sealed traits for exhaustive checking
 * - Higher-order functions for analysis
 */
object CredScan {

  // ============================================================================
  // Type Definitions
  // ============================================================================

  /** Threat severity levels */
  sealed trait Severity extends Ordered[Severity] {
    def priority: Int
    def compare(that: Severity): Int = this.priority - that.priority
  }
  
  case object Critical extends Severity { val priority = 5 }
  case object High extends Severity { val priority = 4 }
  case object Medium extends Severity { val priority = 3 }
  case object Low extends Severity { val priority = 2 }
  case object Info extends Severity { val priority = 1 }

  /** Types of credentials detected */
  sealed trait CredentialType {
    def name: String
    def severity: Severity
  }

  case object AWSAccessKey extends CredentialType {
    val name = "AWS Access Key"
    val severity = Critical
  }
  
  case object AWSSecretKey extends CredentialType {
    val name = "AWS Secret Key"
    val severity = Critical
  }
  
  case object GitHubToken extends CredentialType {
    val name = "GitHub Token"
    val severity = Critical
  }
  
  case object GitHubPAT extends CredentialType {
    val name = "GitHub Personal Access Token"
    val severity = Critical
  }
  
  case object PrivateKey extends CredentialType {
    val name = "Private Key"
    val severity = Critical
  }
  
  case object GoogleAPIKey extends CredentialType {
    val name = "Google API Key"
    val severity = High
  }
  
  case object SlackToken extends CredentialType {
    val name = "Slack Token"
    val severity = High
  }
  
  case object SlackWebhook extends CredentialType {
    val name = "Slack Webhook"
    val severity = High
  }
  
  case object StripeKey extends CredentialType {
    val name = "Stripe API Key"
    val severity = Critical
  }
  
  case object HerokuAPIKey extends CredentialType {
    val name = "Heroku API Key"
    val severity = High
  }
  
  case object TwilioKey extends CredentialType {
    val name = "Twilio API Key"
    val severity = High
  }
  
  case object SendGridKey extends CredentialType {
    val name = "SendGrid API Key"
    val severity = High
  }
  
  case object MailgunKey extends CredentialType {
    val name = "Mailgun API Key"
    val severity = High
  }
  
  case object JWTToken extends CredentialType {
    val name = "JWT Token"
    val severity = Medium
  }
  
  case object GenericPassword extends CredentialType {
    val name = "Generic Password"
    val severity = Medium
  }
  
  case object GenericAPIKey extends CredentialType {
    val name = "Generic API Key"
    val severity = Medium
  }
  
  case object GenericSecret extends CredentialType {
    val name = "Generic Secret"
    val severity = Medium
  }
  
  case object DatabaseURL extends CredentialType {
    val name = "Database Connection String"
    val severity = High
  }
  
  case object IPAddress extends CredentialType {
    val name = "Hardcoded IP Address"
    val severity = Low
  }

  /** A detected credential finding */
  case class Finding(
    credType: CredentialType,
    value: String,
    file: String,
    line: Int,
    context: String,
    masked: String
  ) {
    def severity: Severity = credType.severity
  }

  /** Scan result for a file */
  case class ScanResult(
    file: String,
    findings: List[Finding],
    linesScanned: Int,
    scanTime: Long
  ) {
    def hasCritical: Boolean = findings.exists(_.severity == Critical)
    def hasHigh: Boolean = findings.exists(_.severity == High)
    def findingCount: Int = findings.length
  }

  /** Overall scan summary */
  case class ScanSummary(
    results: List[ScanResult],
    totalFiles: Int,
    totalFindings: Int,
    criticalCount: Int,
    highCount: Int,
    mediumCount: Int,
    lowCount: Int
  )

  // ============================================================================
  // Pattern Definitions
  // ============================================================================

  /** Credential patterns with their types */
  val credentialPatterns: List[(Regex, CredentialType)] = List(
    // AWS
    ("""(?i)(AKIA[0-9A-Z]{16})""".r, AWSAccessKey),
    ("""(?i)aws[_\-]?secret[_\-]?access[_\-]?key['":\s=]+([A-Za-z0-9/+=]{40})""".r, AWSSecretKey),
    
    // GitHub
    ("""(ghp_[a-zA-Z0-9]{36})""".r, GitHubPAT),
    ("""(gho_[a-zA-Z0-9]{36})""".r, GitHubToken),
    ("""(ghu_[a-zA-Z0-9]{36})""".r, GitHubToken),
    ("""(ghs_[a-zA-Z0-9]{36})""".r, GitHubToken),
    ("""(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})""".r, GitHubPAT),
    
    // Private Keys
    ("""-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----""".r, PrivateKey),
    ("""-----BEGIN PGP PRIVATE KEY BLOCK-----""".r, PrivateKey),
    
    // Google
    ("""AIza[0-9A-Za-z\-_]{35}""".r, GoogleAPIKey),
    
    // Slack
    ("""xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*""".r, SlackToken),
    ("""https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+""".r, SlackWebhook),
    
    // Stripe
    ("""sk_live_[0-9a-zA-Z]{24}""".r, StripeKey),
    ("""rk_live_[0-9a-zA-Z]{24}""".r, StripeKey),
    
    // Heroku
    ("""(?i)heroku[_\-]?api[_\-]?key['":\s=]+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})""".r, HerokuAPIKey),
    
    // Twilio
    ("""SK[0-9a-fA-F]{32}""".r, TwilioKey),
    
    // SendGrid
    ("""SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}""".r, SendGridKey),
    
    // Mailgun
    ("""key-[0-9a-zA-Z]{32}""".r, MailgunKey),
    
    // JWT
    ("""eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*""".r, JWTToken),
    
    // Database URLs
    ("""(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s'"]+:[^\s'"]+@[^\s'"]+""".r, DatabaseURL),
    
    // Generic patterns
    ("""(?i)password['":\s=]+['""]?([^'"\s]{8,})['""]?""".r, GenericPassword),
    ("""(?i)api[_\-]?key['":\s=]+['""]?([a-zA-Z0-9_\-]{20,})['""]?""".r, GenericAPIKey),
    ("""(?i)secret['":\s=]+['""]?([a-zA-Z0-9_\-]{20,})['""]?""".r, GenericSecret),
    
    // IP Addresses (internal)
    ("""(?<!\d)(10\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)""".r, IPAddress),
    ("""(?<!\d)(192\.168\.\d{1,3}\.\d{1,3})(?!\d)""".r, IPAddress),
    ("""(?<!\d)(172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?!\d)""".r, IPAddress)
  )

  /** File extensions to skip */
  val skipExtensions: Set[String] = Set(
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".class", ".jar", ".pyc", ".o"
  )

  /** Directories to skip */
  val skipDirs: Set[String] = Set(
    "node_modules", ".git", ".svn", ".hg",
    "vendor", "target", "build", "dist",
    "__pycache__", ".pytest_cache", ".tox",
    ".idea", ".vscode", ".vs"
  )

  // ============================================================================
  // Core Functions
  // ============================================================================

  /**
   * Masks a credential value for safe display
   */
  def maskCredential(value: String): String = {
    if (value.length <= 8) {
      "*" * value.length
    } else {
      val visibleStart = value.take(4)
      val visibleEnd = value.takeRight(4)
      s"$visibleStart${"*" * (value.length - 8)}$visibleEnd"
    }
  }

  /**
   * Scans a single line for credentials
   */
  def scanLine(line: String, lineNum: Int, filePath: String): List[Finding] = {
    credentialPatterns.flatMap { case (pattern, credType) =>
      pattern.findAllMatchIn(line).map { m =>
        val value = if (m.groupCount > 0) m.group(1) else m.matched
        Finding(
          credType = credType,
          value = value,
          file = filePath,
          line = lineNum,
          context = line.trim.take(100),
          masked = maskCredential(value)
        )
      }.toList
    }
  }

  /**
   * Scans a file for credentials
   */
  def scanFile(path: Path): Either[String, ScanResult] = {
    val filePath = path.toString
    val startTime = System.currentTimeMillis()

    Try {
      val lines = Files.readAllLines(path).asScala.toList
      val findings = lines.zipWithIndex.flatMap { case (line, idx) =>
        scanLine(line, idx + 1, filePath)
      }
      
      ScanResult(
        file = filePath,
        findings = findings,
        linesScanned = lines.length,
        scanTime = System.currentTimeMillis() - startTime
      )
    } match {
      case Success(result) => Right(result)
      case Failure(e) => Left(s"Error scanning $filePath: ${e.getMessage}")
    }
  }

  /**
   * Checks if a file should be scanned
   */
  def shouldScanFile(path: Path): Boolean = {
    val fileName = path.getFileName.toString.toLowerCase
    !skipExtensions.exists(fileName.endsWith)
  }

  /**
   * Checks if a directory should be scanned
   */
  def shouldScanDir(path: Path): Boolean = {
    val dirName = path.getFileName.toString
    !skipDirs.contains(dirName)
  }

  /**
   * Recursively finds all scannable files in a directory
   */
  def findFiles(dir: Path): List[Path] = {
    if (!Files.exists(dir)) {
      List.empty
    } else if (Files.isRegularFile(dir)) {
      if (shouldScanFile(dir)) List(dir) else List.empty
    } else {
      Try {
        Files.list(dir).iterator().asScala.toList.flatMap { path =>
          if (Files.isDirectory(path)) {
            if (shouldScanDir(path)) findFiles(path) else List.empty
          } else {
            if (shouldScanFile(path)) List(path) else List.empty
          }
        }
      }.getOrElse(List.empty)
    }
  }

  /**
   * Scans a directory for credentials
   */
  def scanDirectory(dir: Path): ScanSummary = {
    val files = findFiles(dir)
    val results = files.flatMap { path =>
      scanFile(path) match {
        case Right(result) if result.findings.nonEmpty => Some(result)
        case Right(_) => None
        case Left(error) =>
          System.err.println(s"Warning: $error")
          None
      }
    }

    val allFindings = results.flatMap(_.findings)
    
    ScanSummary(
      results = results,
      totalFiles = files.length,
      totalFindings = allFindings.length,
      criticalCount = allFindings.count(_.severity == Critical),
      highCount = allFindings.count(_.severity == High),
      mediumCount = allFindings.count(_.severity == Medium),
      lowCount = allFindings.count(_.severity == Low)
    )
  }

  // ============================================================================
  // Output Formatting
  // ============================================================================

  /** ANSI color codes */
  object Colors {
    val Reset = "\u001b[0m"
    val Red = "\u001b[31m"
    val BrightRed = "\u001b[91m"
    val Yellow = "\u001b[33m"
    val Cyan = "\u001b[36m"
    val Green = "\u001b[32m"
    val Gray = "\u001b[90m"
  }

  def severityColor(severity: Severity): String = severity match {
    case Critical => Colors.BrightRed
    case High => Colors.Red
    case Medium => Colors.Yellow
    case Low => Colors.Cyan
    case Info => Colors.Green
  }

  def printBanner(): Unit = {
    println("""
    |╔══════════════════════════════════════════════════════════════════╗
    |║             NullSec CredScan - Credential Scanner                ║
    |╚══════════════════════════════════════════════════════════════════╝
    """.stripMargin)
  }

  def printFinding(finding: Finding, showContext: Boolean = true): Unit = {
    val color = severityColor(finding.severity)
    val severityStr = finding.severity.toString.toUpperCase
    
    println(s"$color[$severityStr]${Colors.Reset} ${finding.credType.name}")
    println(s"  File: ${finding.file}:${finding.line}")
    println(s"  Value: ${finding.masked}")
    if (showContext) {
      println(s"  ${Colors.Gray}Context: ${finding.context}${Colors.Reset}")
    }
    println()
  }

  def printSummary(summary: ScanSummary): Unit = {
    println("─" * 70)
    println(s"""
    |SCAN SUMMARY
    |  Files scanned:     ${summary.totalFiles}
    |  Total findings:    ${summary.totalFindings}
    |  
    |  ${Colors.BrightRed}Critical:${Colors.Reset}           ${summary.criticalCount}
    |  ${Colors.Red}High:${Colors.Reset}               ${summary.highCount}
    |  ${Colors.Yellow}Medium:${Colors.Reset}             ${summary.mediumCount}
    |  ${Colors.Cyan}Low:${Colors.Reset}                ${summary.lowCount}
    """.stripMargin)
  }

  def printJsonOutput(summary: ScanSummary): Unit = {
    import scala.collection.mutable
    
    val findings = summary.results.flatMap(_.findings).map { f =>
      s"""    {
         |      "type": "${f.credType.name}",
         |      "severity": "${f.severity}",
         |      "file": "${f.file.replace("\\", "\\\\")}",
         |      "line": ${f.line},
         |      "masked_value": "${f.masked}"
         |    }""".stripMargin
    }
    
    println(s"""{
      |  "total_files": ${summary.totalFiles},
      |  "total_findings": ${summary.totalFindings},
      |  "severity_counts": {
      |    "critical": ${summary.criticalCount},
      |    "high": ${summary.highCount},
      |    "medium": ${summary.mediumCount},
      |    "low": ${summary.lowCount}
      |  },
      |  "findings": [
      |${findings.mkString(",\n")}
      |  ]
      |}""".stripMargin)
  }

  // ============================================================================
  // CLI
  // ============================================================================

  case class Config(
    paths: List[String] = List("."),
    json: Boolean = false,
    minSeverity: Severity = Low,
    showHelp: Boolean = false
  )

  def parseArgs(args: Array[String]): Config = {
    def parse(args: List[String], config: Config): Config = args match {
      case Nil => config
      case "--help" :: rest => parse(rest, config.copy(showHelp = true))
      case "-h" :: rest => parse(rest, config.copy(showHelp = true))
      case "--json" :: rest => parse(rest, config.copy(json = true))
      case "-j" :: rest => parse(rest, config.copy(json = true))
      case "--min-severity" :: severity :: rest =>
        val sev = severity.toLowerCase match {
          case "critical" => Critical
          case "high" => High
          case "medium" => Medium
          case "low" => Low
          case _ => Low
        }
        parse(rest, config.copy(minSeverity = sev))
      case "-s" :: severity :: rest =>
        val sev = severity.toLowerCase match {
          case "critical" => Critical
          case "high" => High
          case "medium" => Medium
          case "low" => Low
          case _ => Low
        }
        parse(rest, config.copy(minSeverity = sev))
      case path :: rest if !path.startsWith("-") =>
        parse(rest, config.copy(paths = config.paths :+ path))
      case _ :: rest => parse(rest, config)
    }
    
    val config = parse(args.toList, Config(paths = List.empty))
    if (config.paths.isEmpty) config.copy(paths = List(".")) else config
  }

  def printHelp(): Unit = {
    println("""
    |╔══════════════════════════════════════════════════════════════════╗
    |║             NullSec CredScan - Credential Scanner                ║
    |╚══════════════════════════════════════════════════════════════════╝
    |
    |USAGE:
    |    credscan [OPTIONS] [PATHS...]
    |
    |OPTIONS:
    |    -h, --help              Show this help message
    |    -j, --json              Output results as JSON
    |    -s, --min-severity SEV  Minimum severity to report (critical/high/medium/low)
    |
    |EXAMPLES:
    |    credscan .                    Scan current directory
    |    credscan src/ config/         Scan multiple directories
    |    credscan -j .                 Output as JSON
    |    credscan -s high src/         Only show high+ severity
    |
    |DETECTS:
    |    • AWS Access Keys & Secret Keys
    |    • GitHub Tokens & Personal Access Tokens
    |    • Private Keys (RSA, DSA, EC, PGP)
    |    • Google API Keys
    |    • Slack Tokens & Webhooks
    |    • Stripe API Keys
    |    • Database Connection Strings
    |    • Generic passwords, API keys, secrets
    |    • Hardcoded internal IP addresses
    |
    """.stripMargin)
  }

  def main(args: Array[String]): Unit = {
    val config = parseArgs(args)
    
    if (config.showHelp) {
      printHelp()
      return
    }

    if (!config.json) {
      printBanner()
      println(s"Scanning: ${config.paths.mkString(", ")}\n")
    }

    val allSummaries = config.paths.map { pathStr =>
      scanDirectory(Paths.get(pathStr))
    }

    // Merge summaries
    val merged = ScanSummary(
      results = allSummaries.flatMap(_.results),
      totalFiles = allSummaries.map(_.totalFiles).sum,
      totalFindings = allSummaries.map(_.totalFindings).sum,
      criticalCount = allSummaries.map(_.criticalCount).sum,
      highCount = allSummaries.map(_.highCount).sum,
      mediumCount = allSummaries.map(_.mediumCount).sum,
      lowCount = allSummaries.map(_.lowCount).sum
    )

    // Filter by minimum severity
    val filteredResults = merged.results.map { result =>
      result.copy(findings = result.findings.filter(_.severity >= config.minSeverity))
    }.filter(_.findings.nonEmpty)

    val filteredSummary = merged.copy(
      results = filteredResults,
      totalFindings = filteredResults.flatMap(_.findings).length
    )

    if (config.json) {
      printJsonOutput(filteredSummary)
    } else {
      filteredSummary.results.foreach { result =>
        println(s"${Colors.Gray}── ${result.file} ──${Colors.Reset}\n")
        result.findings.foreach(printFinding(_))
      }
      printSummary(filteredSummary)

      // Exit with error code if critical findings
      if (filteredSummary.criticalCount > 0) {
        System.exit(1)
      }
    }
  }
}
