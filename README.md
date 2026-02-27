# NullSec CredScan

Credential scanner built with Scala 3, demonstrating functional programming patterns for security analysis.

## Security Features

- **Option Types**: Safe handling of nullable values
- **Either Types**: Explicit error handling without exceptions
- **Case Classes**: Immutable data structures for findings
- **Sealed Traits**: Exhaustive pattern matching for types
- **Pattern Matching**: Type-safe credential classification
- **Higher-Order Functions**: Composable analysis pipeline

## Detection Capabilities

| Category | Patterns |
|----------|----------|
| **Cloud** | AWS Access Keys, AWS Secret Keys, Google API Keys |
| **Source Control** | GitHub PATs, GitHub Tokens (ghp_, gho_, ghu_, ghs_) |
| **Cryptographic** | RSA/DSA/EC/PGP Private Keys |
| **Communication** | Slack Tokens, Slack Webhooks |
| **Payment** | Stripe Live Keys |
| **Infrastructure** | Heroku API Keys, Database URLs |
| **Email** | SendGrid Keys, Mailgun Keys, Twilio Keys |
| **Auth** | JWT Tokens |
| **Generic** | Passwords, API Keys, Secrets |
| **Network** | Hardcoded Internal IPs |

## Installation

```bash
# Compile
sbt compile

# Create fat JAR
sbt assembly

# Run
java -jar target/scala-3.3.1/credscan.jar
```

## Usage

```bash
# Scan current directory
credscan .

# Scan specific paths
credscan src/ config/ scripts/

# JSON output
credscan --json .

# Filter by severity
credscan --min-severity high src/

# Show help
credscan --help
```

## API Usage

```scala
import nullsec.credscan.CredScan._
import java.nio.file.Paths

// Scan a directory
val summary = scanDirectory(Paths.get("./src"))

// Check results
println(s"Found ${summary.totalFindings} credentials")
println(s"Critical: ${summary.criticalCount}")

// Scan a single file
scanFile(Paths.get("config.yml")) match {
  case Right(result) =>
    result.findings.foreach { finding =>
      println(s"[${finding.severity}] ${finding.credType.name}")
      println(s"  ${finding.masked}")
    }
  case Left(error) =>
    println(s"Error: $error")
}

// Scan a single line
val findings = scanLine("api_key = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'", 1, "test.py")
```

## Severity Levels

| Level | Description | Examples |
|-------|-------------|----------|
| **Critical** | Direct access credentials | AWS keys, GitHub tokens, Private keys, Stripe keys |
| **High** | Service credentials | Slack tokens, Heroku keys, Database URLs |
| **Medium** | Generic secrets | JWT tokens, Generic passwords/keys |
| **Low** | Informational | Hardcoded internal IPs |

## Output Formats

### Console (Default)
```
[CRITICAL] AWS Access Key
  File: config/settings.py:42
  Value: AKIA****************WXYZ
  Context: AWS_ACCESS_KEY = "AKIA..."
```

### JSON
```json
{
  "total_files": 150,
  "total_findings": 3,
  "severity_counts": {
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0
  },
  "findings": [...]
}
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: Scan for credentials
  run: |
    java -jar credscan.jar --json . > results.json
    if [ $? -ne 0 ]; then
      echo "Critical credentials found!"
      exit 1
    fi
```

## Excluded Paths

Automatically skips:
- Binary files (.exe, .dll, .so, .jar, etc.)
- Media files (.jpg, .mp4, .pdf, etc.)
- Archives (.zip, .tar, .gz, etc.)
- Build directories (node_modules, target, dist, etc.)
- VCS directories (.git, .svn, .hg)

## License

MIT License - Part of the NullSec Framework

## Author

- GitHub: [bad-antics](https://github.com/bad-antics)
- Twitter: [x.com/AnonAntics](https://x.com/AnonAntics)
