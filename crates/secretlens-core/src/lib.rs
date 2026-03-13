pub mod finding;
pub mod rule;
pub mod protocol;
pub mod error;

pub use finding::{Finding, FindingType, Severity};
pub use rule::{Rule, AnalyzerKind, AstPattern, RuleConditions};
pub use protocol::{
    ProtocolRequest, ProtocolResponse, AnalyzePayload, ResolvePayload,
    AnalyzeResult, ResolveResult, ErrorResult, FileChange, AiProviderConfig,
    OutputFormat,
};
pub use error::CoreError;
