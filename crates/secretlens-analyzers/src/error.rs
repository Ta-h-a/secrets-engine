use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error("Regex compilation failed for rule '{rule_id}': {source}")]
    RegexCompile {
        rule_id: String,
        #[source]
        source: regex::Error,
    },

    #[error("Python AST parse error in '{file_path}': {message}")]
    PythonParse { file_path: String, message: String },

    #[error("JavaScript AST parse error in '{file_path}': {message}")]
    JsParse { file_path: String, message: String },

    #[error("Unsupported language '{language}' for AST analysis")]
    UnsupportedLanguage { language: String },
}
