use secretlens_core::{AnalyzerKind, Rule, RuleConditions};

/// Returns the built-in default rules compiled directly into the binary.
/// These are used as fallback when no rules directory is available or valid.
/// All 20 rules mirror the YAML files in projectInRust/rules/.
pub fn default_rules() -> Vec<Rule> {
    vec![
        // -- Security: Credentials & Keys -----------------------------------
        Rule {
            id: "SEC-001".to_string(),
            name: "Hardcoded AWS Access Key".to_string(),
            finding_type: "security".to_string(),
            severity: "critical".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r"(AKIA[0-9A-Z]{16})".to_string(),
            message: "Hardcoded AWS access key detected".to_string(),
            title: "AWS Access Key Exposed".to_string(),
            description: "An AWS IAM access key ID was found hardcoded in source code.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Remove the hardcoded key immediately".to_string(),
                "Rotate the compromised key via IAM or the code-guard rotation engine".to_string(),
                "Store the key in AWS Secrets Manager or environment variables".to_string(),
            ],
            references: vec![
                "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html".to_string(),
            ],
            tags: vec!["aws".to_string(), "credentials".to_string(), "iam".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec![
                    "node_modules/".to_string(),
                    "vendor/".to_string(),
                    ".git/".to_string(),
                ],
            },
        },
        Rule {
            id: "SEC-002".to_string(),
            name: "Hardcoded API Key".to_string(),
            finding_type: "security".to_string(),
            severity: "high".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r#"(?i)(api[_\-\s]?key|apikey)\s*[=:]\s*["']?([A-Za-z0-9\-_]{20,})["']?"#.to_string(),
            message: "Hardcoded API key detected".to_string(),
            title: "Hardcoded API Key".to_string(),
            description: "A hardcoded API key was detected in source code.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Move API keys to environment variables or a secrets manager".to_string(),
            ],
            references: vec![],
            tags: vec!["api-key".to_string(), "credentials".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        Rule {
            id: "SEC-003".to_string(),
            name: "Google API Key".to_string(),
            finding_type: "security".to_string(),
            severity: "high".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r"AIza[0-9A-Za-z\-_]{35}".to_string(),
            message: "Google API key detected".to_string(),
            title: "Google API Key Exposed".to_string(),
            description: "A Google API key was found hardcoded in source code.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Restrict API key usage in the Google Cloud Console".to_string(),
                "Rotate the key immediately".to_string(),
            ],
            references: vec!["https://cloud.google.com/docs/authentication/api-keys".to_string()],
            tags: vec!["google".to_string(), "api-key".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        Rule {
            id: "SEC-004".to_string(),
            name: "Hardcoded Password".to_string(),
            finding_type: "security".to_string(),
            severity: "high".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r#"(?i)(password|passwd|pwd)\s*[=:]\s*["']([^"']{6,})["']"#.to_string(),
            message: "Hardcoded password detected".to_string(),
            title: "Hardcoded Password".to_string(),
            description: "A hardcoded password was found in source code.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Replace with environment variable or secrets manager reference".to_string(),
            ],
            references: vec![],
            tags: vec!["password".to_string(), "credentials".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec![
                    "node_modules/".to_string(),
                    ".git/".to_string(),
                    "test/".to_string(),
                    "tests/".to_string(),
                ],
            },
        },
        Rule {
            id: "SEC-005".to_string(),
            name: "Stripe API Key".to_string(),
            finding_type: "security".to_string(),
            severity: "critical".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r"(sk|rk)_(live|test)_[0-9a-zA-Z]{24,}".to_string(),
            message: "Stripe API key detected".to_string(),
            title: "Stripe API Key Exposed".to_string(),
            description: "A Stripe secret or restricted key was found hardcoded.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec!["Rotate the key immediately in the Stripe dashboard".to_string()],
            references: vec!["https://stripe.com/docs/keys".to_string()],
            tags: vec!["stripe".to_string(), "payment".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        Rule {
            id: "SEC-006".to_string(),
            name: "SendGrid API Key".to_string(),
            finding_type: "security".to_string(),
            severity: "high".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}".to_string(),
            message: "SendGrid API key detected".to_string(),
            title: "SendGrid API Key Exposed".to_string(),
            description: "A SendGrid API key was found hardcoded in source code.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec!["Rotate the key in the SendGrid dashboard immediately".to_string()],
            references: vec![],
            tags: vec!["sendgrid".to_string(), "email".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        Rule {
            id: "SEC-007".to_string(),
            name: "Slack Webhook URL".to_string(),
            finding_type: "security".to_string(),
            severity: "medium".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+".to_string(),
            message: "Slack incoming webhook URL detected".to_string(),
            title: "Slack Webhook URL Exposed".to_string(),
            description: "A Slack webhook URL was found hardcoded - allows posting to a Slack channel.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec!["Revoke the webhook in Slack App settings and create a new one".to_string()],
            references: vec![],
            tags: vec!["slack".to_string(), "webhook".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        Rule {
            id: "SEC-008".to_string(),
            name: "Twilio Credentials".to_string(),
            finding_type: "security".to_string(),
            severity: "high".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r#"(?i)(twilio[_\-\s]?(auth[_\-\s]?token|account[_\-\s]?sid))\s*[=:]\s*["']?([A-Za-z0-9]{32,34})["']?"#.to_string(),
            message: "Twilio credentials detected".to_string(),
            title: "Twilio Credentials Exposed".to_string(),
            description: "Twilio account SID or auth token found hardcoded.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec!["Rotate Twilio credentials in the Twilio Console".to_string()],
            references: vec![],
            tags: vec!["twilio".to_string(), "sms".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        Rule {
            id: "SEC-009".to_string(),
            name: "Cloudflare API Token".to_string(),
            finding_type: "security".to_string(),
            severity: "high".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r"[A-Za-z0-9_-]{40}".to_string(),
            message: "Possible Cloudflare API token detected".to_string(),
            title: "Cloudflare API Token".to_string(),
            description: "A possible Cloudflare API token was found hardcoded.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec!["Rotate the token in the Cloudflare dashboard".to_string()],
            references: vec![],
            tags: vec!["cloudflare".to_string(), "api-token".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        Rule {
            id: "SEC-010".to_string(),
            name: "GitHub Token".to_string(),
            finding_type: "security".to_string(),
            severity: "critical".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r"gh[pousr]_[A-Za-z0-9_]{36,}".to_string(),
            message: "GitHub personal access or OAuth token detected".to_string(),
            title: "GitHub Token Exposed".to_string(),
            description: "A GitHub token was found hardcoded - allows access to GitHub resources.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Revoke the token at https://github.com/settings/tokens".to_string(),
                "Use GitHub Actions secrets or environment variables instead".to_string(),
            ],
            references: vec!["https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation".to_string()],
            tags: vec!["github".to_string(), "token".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        Rule {
            id: "SEC-011".to_string(),
            name: "OpenAI API Key".to_string(),
            finding_type: "security".to_string(),
            severity: "critical".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r"sk-proj-[A-Za-z0-9_\-]{40,}".to_string(),
            message: "OpenAI API key detected".to_string(),
            title: "OpenAI API Key Exposed".to_string(),
            description: "An OpenAI API key was found hardcoded - incurs billing charges on your account.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Revoke the key at https://platform.openai.com/api-keys".to_string(),
                "Use environment variables to inject the key at runtime".to_string(),
            ],
            references: vec!["https://platform.openai.com/docs/guides/production-best-practices".to_string()],
            tags: vec!["openai".to_string(), "llm".to_string(), "api-key".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        Rule {
            id: "SEC-012".to_string(),
            name: "Anthropic API Key".to_string(),
            finding_type: "security".to_string(),
            severity: "critical".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r"sk-ant-[A-Za-z0-9_\-]{40,}".to_string(),
            message: "Anthropic API key detected".to_string(),
            title: "Anthropic API Key Exposed".to_string(),
            description: "An Anthropic Claude API key was found hardcoded.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Revoke the key at https://console.anthropic.com/settings/keys".to_string(),
            ],
            references: vec![],
            tags: vec!["anthropic".to_string(), "llm".to_string(), "api-key".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        Rule {
            id: "SEC-013".to_string(),
            name: "PEM Private Key".to_string(),
            finding_type: "security".to_string(),
            severity: "critical".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----".to_string(),
            message: "PEM private key detected in source code".to_string(),
            title: "Private Key Exposed".to_string(),
            description: "A PEM-encoded private key was found hardcoded - this is a critical security risk.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Never commit private keys to source control".to_string(),
                "Rotate the key pair immediately".to_string(),
                "Use a secrets manager to store and inject private keys".to_string(),
            ],
            references: vec![],
            tags: vec!["private-key".to_string(), "pem".to_string(), "tls".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec![".git/".to_string()],
            },
        },
        Rule {
            id: "SEC-014".to_string(),
            name: "JWT Token".to_string(),
            finding_type: "security".to_string(),
            severity: "medium".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+".to_string(),
            message: "JWT token detected in source code".to_string(),
            title: "JWT Token Hardcoded".to_string(),
            description: "A hardcoded JWT token was found. Hardcoded tokens can be replayed and are difficult to revoke.".to_string(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Never hardcode JWT tokens - generate them at runtime".to_string(),
                "Rotate any signing keys associated with this token".to_string(),
            ],
            references: vec![],
            tags: vec!["jwt".to_string(), "token".to_string(), "auth".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec![
                    "node_modules/".to_string(),
                    ".git/".to_string(),
                    "test/".to_string(),
                    "tests/".to_string(),
                ],
            },
        },
        Rule {
            id: "SEC-015".to_string(),
            name: "SQL Injection Risk".to_string(),
            finding_type: "security".to_string(),
            severity: "high".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r#"(?i)(execute|exec|query)\s*\(\s*["']?\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b[^"';)]*\+\s*"#.to_string(),
            message: "Potential SQL injection via string concatenation".to_string(),
            title: "SQL Injection Risk".to_string(),
            description: "SQL query built via string concatenation - susceptible to SQL injection.".to_string(),
            redact: false,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Use parameterized queries or prepared statements".to_string(),
                "Use an ORM with automatic query parameterization".to_string(),
            ],
            references: vec![
                "https://owasp.org/www-community/attacks/SQL_Injection".to_string(),
            ],
            tags: vec!["sql".to_string(), "injection".to_string(), "owasp".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        // -- Performance -----------------------------------------------------
        Rule {
            id: "PERF-001".to_string(),
            name: "Synchronous File I/O in Async Context".to_string(),
            finding_type: "performance".to_string(),
            severity: "medium".to_string(),
            language: "javascript".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r"\bfs\.(readFileSync|writeFileSync|appendFileSync|existsSync|statSync|mkdirSync|readdirSync|unlinkSync|renameSync)\b".to_string(),
            message: "Synchronous file I/O call detected - blocks the event loop".to_string(),
            title: "Synchronous fs Call".to_string(),
            description: "Synchronous fs methods block Node.js's event loop, degrading throughput under load.".to_string(),
            redact: false,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Replace with the async promise-based equivalent (fs.promises.*)".to_string(),
                "Or use the callback-based API to avoid blocking".to_string(),
            ],
            references: vec![
                "https://nodejs.org/api/fs.html#promises-api".to_string(),
            ],
            tags: vec!["nodejs".to_string(), "performance".to_string(), "io".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        // -- AST - Python ----------------------------------------------------
        Rule {
            id: "AST-PY-001".to_string(),
            name: "Dangerous eval() in Python".to_string(),
            finding_type: "security".to_string(),
            severity: "critical".to_string(),
            language: "python".to_string(),
            analyzer: AnalyzerKind::Ast,
            pattern: "call:eval".to_string(),
            message: "Dangerous use of eval() - executes arbitrary Python code".to_string(),
            title: "Python eval() Usage".to_string(),
            description: "eval() is dangerous because it executes arbitrary Python code, including user-supplied input.".to_string(),
            redact: false,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Replace with ast.literal_eval() for safe literal evaluation".to_string(),
                "Use json.loads() for JSON data".to_string(),
            ],
            references: vec![
                "https://docs.python.org/3/library/functions.html#eval".to_string(),
            ],
            tags: vec!["python".to_string(), "code-execution".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        Rule {
            id: "AST-PY-002".to_string(),
            name: "Dangerous exec() in Python".to_string(),
            finding_type: "security".to_string(),
            severity: "critical".to_string(),
            language: "python".to_string(),
            analyzer: AnalyzerKind::Ast,
            pattern: "call:exec".to_string(),
            message: "Dangerous use of exec() - executes arbitrary Python code".to_string(),
            title: "Python exec() Usage".to_string(),
            description: "exec() dynamically executes Python code. Using it with user input creates remote code execution vulnerabilities.".to_string(),
            redact: false,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Avoid exec() entirely; refactor to explicit code paths".to_string(),
            ],
            references: vec![
                "https://docs.python.org/3/library/functions.html#exec".to_string(),
            ],
            tags: vec!["python".to_string(), "code-execution".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
        // -- AST - JavaScript ------------------------------------------------
        Rule {
            id: "AST-JS-001".to_string(),
            name: "Dangerous eval() in JavaScript".to_string(),
            finding_type: "security".to_string(),
            severity: "critical".to_string(),
            language: "javascript".to_string(),
            analyzer: AnalyzerKind::Ast,
            pattern: "call:eval".to_string(),
            message: "Dangerous use of eval() detected - executes arbitrary JavaScript".to_string(),
            title: "JavaScript eval() Usage".to_string(),
            description: "eval() executes a string as JavaScript code. This is an XSS and RCE risk.".to_string(),
            redact: false,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Replace eval() with JSON.parse() for data".to_string(),
                "Enable CSP to block eval() in browsers".to_string(),
            ],
            references: vec![
                "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!".to_string(),
            ],
            tags: vec!["javascript".to_string(), "code-execution".to_string(), "xss".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec![
                    "node_modules/".to_string(),
                    ".git/".to_string(),
                    "test/".to_string(),
                    "tests/".to_string(),
                ],
            },
        },
        Rule {
            id: "AST-JS-002".to_string(),
            name: "Weak Cryptographic Algorithm in JavaScript".to_string(),
            finding_type: "security".to_string(),
            severity: "high".to_string(),
            language: "javascript".to_string(),
            analyzer: AnalyzerKind::Ast,
            pattern: "crypto_weak:md5".to_string(),
            message: "Weak cryptographic algorithm (MD5) detected".to_string(),
            title: "Weak Crypto: MD5".to_string(),
            description: "MD5 is cryptographically broken and must not be used for security purposes.".to_string(),
            redact: false,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![
                "Replace MD5 with SHA-256 or SHA-3 for integrity checks".to_string(),
                "Use bcrypt/Argon2 for password hashing".to_string(),
            ],
            references: vec![
                "https://owasp.org/www-community/vulnerabilities/Use_of_Obsolete_Cryptographic_Functions".to_string(),
            ],
            tags: vec!["javascript".to_string(), "crypto".to_string(), "owasp".to_string()],
            conditions: RuleConditions {
                exclude_paths: vec!["node_modules/".to_string(), ".git/".to_string()],
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rules_are_non_empty() {
        let rules = default_rules();
        assert!(!rules.is_empty());
    }

    #[test]
    fn default_rules_all_pass_validation() {
        for rule in default_rules() {
            rule.validate()
                .unwrap_or_else(|e| panic!("Rule '{}' failed validation: {}", rule.id, e));
        }
    }

    #[test]
    fn default_rules_have_unique_ids() {
        let rules = default_rules();
        let mut ids = std::collections::HashSet::new();
        for rule in &rules {
            assert!(ids.insert(&rule.id), "Duplicate rule ID: {}", rule.id);
        }
    }

    #[test]
    fn default_rules_regex_patterns_compile() {
        for rule in default_rules() {
            if rule.analyzer == AnalyzerKind::Regex {
                regex::Regex::new(&rule.pattern)
                    .unwrap_or_else(|e| panic!("Rule '{}' has invalid regex: {}", rule.id, e));
            }
        }
    }
}
