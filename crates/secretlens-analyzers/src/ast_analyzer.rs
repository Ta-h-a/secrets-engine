use secretlens_core::{AstPattern, FileChange, Finding, FindingType, Rule, Severity};
use tracing::warn;
use uuid::Uuid;

/// AST-based analyzer - uses pure Rust parsers, zero subprocess spawning.
///
/// Supported languages:
///   - Python: rustpython-parser
///   - JavaScript / TypeScript: oxc_parser
pub struct AstAnalyzer;

impl AstAnalyzer {
    /// Analyze a single file against a slice of AST rules.
    pub fn analyze(file: &FileChange, rules: &[Rule], line_table: &[usize]) -> Vec<Finding> {
        let lang = file.language();
        let mut findings = Vec::new();

        // Partition rules by language before parsing (avoid parsing if no rules apply)
        let applicable_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.language == lang || r.language == "*")
            .filter(|r| !r.should_exclude_path(&file.file_path))
            .collect();

        if applicable_rules.is_empty() {
            return findings;
        }

        match lang {
            "python" => {
                findings.extend(analyze_python(file, &applicable_rules, line_table));
            }
            "javascript" | "typescript" => {
                findings.extend(analyze_js_ts(file, &applicable_rules, line_table));
            }
            other => {
                warn!(
                    "AST analysis not supported for language '{}' (file: {})",
                    other, file.file_path
                );
            }
        }

        findings
    }
}

// --- Python ------------------------------------------------------------------

fn analyze_python(file: &FileChange, rules: &[&Rule], line_table: &[usize]) -> Vec<Finding> {
    use rustpython_parser::{ast as py_ast, Parse};

    let mut findings = Vec::new();

    let stmts = match py_ast::Suite::parse(&file.content, &file.file_path) {
        Ok(s) => s,
        Err(e) => {
            warn!("Python parse error in '{}': {}", file.file_path, e);
            return findings;
        }
    };

    // Walk the AST collecting call expressions: (func_name, byte_offset)
    let calls = collect_python_calls(&stmts);

    for (func_name, byte_offset) in &calls {
        let line = crate::regex_analyzer::offset_to_line(*byte_offset, line_table);
        for rule in rules {
            let pattern = match AstPattern::parse(&rule.pattern) {
                Ok(p) => p,
                Err(e) => {
                    warn!("Invalid AST pattern in rule '{}': {}", rule.id, e);
                    continue;
                }
            };

            let matched = match &pattern {
                AstPattern::Call { name } => func_name == name,
                AstPattern::Import { .. } => false,
                AstPattern::MemberCall { .. } => false,
                AstPattern::CryptoWeak { .. } => false,
            };

            if matched {
                findings.push(make_finding(file, line, rule));
            }
        }
    }

    // Walk imports: (module_name, byte_offset)
    let imports = collect_python_imports(&stmts);
    for (module_name, byte_offset) in &imports {
        let line = crate::regex_analyzer::offset_to_line(*byte_offset, line_table);
        for rule in rules {
            let pattern = match AstPattern::parse(&rule.pattern) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if let AstPattern::Import { module } = &pattern {
                if module_name == module || module_name.starts_with(&format!("{}.", module)) {
                    findings.push(make_finding(file, line, rule));
                }
            }
        }
    }

    findings
}

/// Walk Python AST and collect (function_name, byte_offset) for Call nodes.
/// We collect byte offsets here and convert to line numbers in the caller
/// using the pre-built line table (O(log n) per lookup).
fn collect_python_calls(stmts: &[rustpython_parser::ast::Stmt]) -> Vec<(String, usize)> {
    let mut calls = Vec::new();
    for stmt in stmts {
        collect_calls_in_stmt(stmt, &mut calls);
    }
    calls
}

fn collect_calls_in_stmt(stmt: &rustpython_parser::ast::Stmt, out: &mut Vec<(String, usize)>) {
    use rustpython_parser::ast::Stmt;

    match stmt {
        Stmt::Expr(expr_stmt) => collect_calls_in_expr(&expr_stmt.value, out),
        Stmt::Assign(assign) => collect_calls_in_expr(&assign.value, out),
        Stmt::AugAssign(aug) => collect_calls_in_expr(&aug.value, out),
        Stmt::AnnAssign(ann) => {
            if let Some(val) = &ann.value {
                collect_calls_in_expr(val, out);
            }
        }
        Stmt::Return(ret) => {
            if let Some(val) = &ret.value {
                collect_calls_in_expr(val, out);
            }
        }
        Stmt::If(if_stmt) => {
            collect_calls_in_expr(&if_stmt.test, out);
            for s in &if_stmt.body {
                collect_calls_in_stmt(s, out);
            }
            for s in &if_stmt.orelse {
                collect_calls_in_stmt(s, out);
            }
        }
        Stmt::While(while_stmt) => {
            collect_calls_in_expr(&while_stmt.test, out);
            for s in &while_stmt.body {
                collect_calls_in_stmt(s, out);
            }
        }
        Stmt::For(for_stmt) => {
            collect_calls_in_expr(&for_stmt.iter, out);
            for s in &for_stmt.body {
                collect_calls_in_stmt(s, out);
            }
        }
        Stmt::FunctionDef(func) => {
            for s in &func.body {
                collect_calls_in_stmt(s, out);
            }
        }
        Stmt::AsyncFunctionDef(func) => {
            for s in &func.body {
                collect_calls_in_stmt(s, out);
            }
        }
        Stmt::ClassDef(cls) => {
            for s in &cls.body {
                collect_calls_in_stmt(s, out);
            }
        }
        Stmt::With(with) => {
            for s in &with.body {
                collect_calls_in_stmt(s, out);
            }
        }
        Stmt::Try(try_stmt) => {
            for s in &try_stmt.body {
                collect_calls_in_stmt(s, out);
            }
            for s in &try_stmt.orelse {
                collect_calls_in_stmt(s, out);
            }
            for s in &try_stmt.finalbody {
                collect_calls_in_stmt(s, out);
            }
        }
        _ => {}
    }
}

fn collect_calls_in_expr(expr: &rustpython_parser::ast::Expr, out: &mut Vec<(String, usize)>) {
    use rustpython_parser::ast::Expr;

    match expr {
        Expr::Call(call) => {
            // .range returns TextRange (byte range); .start() returns TextSize
            // TextSize has .to_usize() -> byte offset
            let byte_offset = call.range.start().to_usize();
            if let Some(name) = extract_call_name(&call.func) {
                out.push((name, byte_offset));
            }
            for arg in &call.args {
                collect_calls_in_expr(arg, out);
            }
        }
        Expr::BinOp(binop) => {
            collect_calls_in_expr(&binop.left, out);
            collect_calls_in_expr(&binop.right, out);
        }
        Expr::IfExp(ifexp) => {
            collect_calls_in_expr(&ifexp.test, out);
            collect_calls_in_expr(&ifexp.body, out);
            collect_calls_in_expr(&ifexp.orelse, out);
        }
        Expr::Attribute(attr) => {
            collect_calls_in_expr(&attr.value, out);
        }
        Expr::List(list) => {
            for elt in &list.elts {
                collect_calls_in_expr(elt, out);
            }
        }
        Expr::Tuple(tup) => {
            for elt in &tup.elts {
                collect_calls_in_expr(elt, out);
            }
        }
        _ => {}
    }
}

fn extract_call_name(expr: &rustpython_parser::ast::Expr) -> Option<String> {
    use rustpython_parser::ast::Expr;
    match expr {
        Expr::Name(name) => Some(name.id.to_string()),
        Expr::Attribute(attr) => {
            let obj = extract_call_name(&attr.value)?;
            Some(format!("{}.{}", obj, attr.attr))
        }
        _ => None,
    }
}

/// Collect (module_name, byte_offset) from Python import statements.
fn collect_python_imports(stmts: &[rustpython_parser::ast::Stmt]) -> Vec<(String, usize)> {
    use rustpython_parser::ast::Stmt;

    let mut imports = Vec::new();
    for stmt in stmts {
        match stmt {
            Stmt::Import(imp) => {
                let byte_offset = imp.range.start().to_usize();
                for alias in &imp.names {
                    imports.push((alias.name.to_string(), byte_offset));
                }
            }
            Stmt::ImportFrom(imp) => {
                let byte_offset = imp.range.start().to_usize();
                if let Some(module) = &imp.module {
                    imports.push((module.to_string(), byte_offset));
                }
            }
            _ => {}
        }
    }
    imports
}

// --- JavaScript / TypeScript -------------------------------------------------

fn analyze_js_ts(file: &FileChange, rules: &[&Rule], line_table: &[usize]) -> Vec<Finding> {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;

    let mut findings = Vec::new();

    let allocator = Allocator::default();
    let source_type = if file.file_path.ends_with(".ts") || file.file_path.ends_with(".tsx") {
        SourceType::ts()
    } else {
        SourceType::mjs()
    };

    let ret = Parser::new(&allocator, &file.content, source_type).parse();

    if !ret.errors.is_empty() {
        warn!(
            "JS/TS parse errors in '{}': {} error(s) - continuing with partial AST",
            file.file_path,
            ret.errors.len()
        );
    }

    let mut visitor = JsAstVisitor::new(rules, line_table, file);
    visitor.walk_program(&ret.program);
    findings.extend(visitor.findings);

    findings
}

struct JsAstVisitor<'a> {
    rules: &'a [&'a Rule],
    line_table: &'a [usize],
    file: &'a FileChange,
    pub findings: Vec<Finding>,
}

impl<'a> JsAstVisitor<'a> {
    fn new(rules: &'a [&'a Rule], line_table: &'a [usize], file: &'a FileChange) -> Self {
        Self {
            rules,
            line_table,
            file,
            findings: Vec::new(),
        }
    }

    fn walk_program(&mut self, program: &oxc_ast::ast::Program) {
        for stmt in &program.body {
            self.walk_statement(stmt);
        }
    }

    fn walk_statement(&mut self, stmt: &oxc_ast::ast::Statement) {
        use oxc_ast::ast::Statement;
        match stmt {
            Statement::ExpressionStatement(expr_stmt) => {
                self.walk_expression(&expr_stmt.expression);
            }
            Statement::VariableDeclaration(var_decl) => {
                for decl in &var_decl.declarations {
                    if let Some(init) = &decl.init {
                        self.walk_expression(init);
                    }
                }
            }
            Statement::ReturnStatement(ret) => {
                if let Some(arg) = &ret.argument {
                    self.walk_expression(arg);
                }
            }
            Statement::IfStatement(if_stmt) => {
                self.walk_expression(&if_stmt.test);
                self.walk_statement(&if_stmt.consequent);
                if let Some(alt) = &if_stmt.alternate {
                    self.walk_statement(alt);
                }
            }
            Statement::WhileStatement(while_stmt) => {
                self.walk_expression(&while_stmt.test);
                self.walk_statement(&while_stmt.body);
            }
            Statement::ForStatement(for_stmt) => {
                // body is Statement (not Option)
                self.walk_statement(&for_stmt.body);
            }
            Statement::BlockStatement(block) => {
                for s in &block.body {
                    self.walk_statement(s);
                }
            }
            Statement::FunctionDeclaration(func) => {
                if let Some(body) = &func.body {
                    for s in &body.statements {
                        self.walk_statement(s);
                    }
                }
            }
            _ => {}
        }
    }

    fn walk_expression(&mut self, expr: &oxc_ast::ast::Expression) {
        use oxc_ast::ast::Expression;

        match expr {
            Expression::CallExpression(call) => {
                let byte_offset = call.span.start as usize;
                let line = crate::regex_analyzer::offset_to_line(byte_offset, self.line_table);

                match &call.callee {
                    Expression::Identifier(ident) => {
                        let name = ident.name.as_str();
                        self.check_call_rules(name, line);
                    }
                    Expression::StaticMemberExpression(member) => {
                        let obj = extract_js_object_name(&member.object);
                        let method = member.property.name.as_str();
                        self.check_member_call_rules(&obj, method, line);
                        self.check_crypto_in_call(&call.arguments, line);
                    }
                    _ => {}
                }

                // In oxc 0.29, Argument inherits Expression variants via inherit_variants!
                // Use as_expression() to get the inner &Expression
                for arg in &call.arguments {
                    if let Some(arg_expr) = arg.as_expression() {
                        self.walk_expression(arg_expr);
                    }
                }
            }
            Expression::BinaryExpression(bin) => {
                self.walk_expression(&bin.left);
                self.walk_expression(&bin.right);
            }
            Expression::ConditionalExpression(cond) => {
                self.walk_expression(&cond.test);
                self.walk_expression(&cond.consequent);
                self.walk_expression(&cond.alternate);
            }
            Expression::ArrayExpression(arr) => {
                for el in &arr.elements {
                    // ArrayExpressionElement inherits Expression variants; use as_expression()
                    if let Some(e) = el.as_expression() {
                        self.walk_expression(e);
                    }
                }
            }
            Expression::AssignmentExpression(assign) => {
                self.walk_expression(&assign.right);
            }
            _ => {}
        }
    }

    fn check_call_rules(&mut self, func_name: &str, line: u32) {
        for rule in self.rules {
            let Ok(pattern) = AstPattern::parse(&rule.pattern) else {
                continue;
            };
            if let AstPattern::Call { name } = &pattern {
                if name == func_name {
                    self.findings.push(make_finding(self.file, line, rule));
                }
            }
        }
    }

    fn check_member_call_rules(&mut self, obj: &str, method: &str, line: u32) {
        for rule in self.rules {
            let Ok(pattern) = AstPattern::parse(&rule.pattern) else {
                continue;
            };
            if let AstPattern::MemberCall {
                object,
                method: expected_method,
            } = &pattern
            {
                if object == obj && expected_method == method {
                    self.findings.push(make_finding(self.file, line, rule));
                }
            }
        }
    }

    fn check_crypto_in_call(
        &mut self,
        args: &oxc_allocator::Vec<oxc_ast::ast::Argument>,
        line: u32,
    ) {
        for arg in args {
            // In oxc 0.29, use as_expression() then match on StringLiteral
            if let Some(oxc_ast::ast::Expression::StringLiteral(s)) = arg.as_expression() {
                let algo = s.value.to_lowercase();
                for rule in self.rules {
                    let Ok(pattern) = AstPattern::parse(&rule.pattern) else {
                        continue;
                    };
                    if let AstPattern::CryptoWeak { algorithm } = &pattern {
                        if algorithm.to_lowercase() == algo {
                            self.findings.push(make_finding(self.file, line, rule));
                        }
                    }
                }
            }
        }
    }
}

fn extract_js_object_name(expr: &oxc_ast::ast::Expression) -> String {
    use oxc_ast::ast::Expression;
    match expr {
        Expression::Identifier(ident) => ident.name.to_string(),
        Expression::StaticMemberExpression(member) => {
            let obj = extract_js_object_name(&member.object);
            format!("{}.{}", obj, member.property.name)
        }
        _ => String::new(),
    }
}

// --- Shared helper -----------------------------------------------------------

fn make_finding(file: &FileChange, line: u32, rule: &Rule) -> Finding {
    let mut f = Finding::new(
        file.file_path.clone(),
        line,
        FindingType::from_str(&rule.finding_type),
        Severity::from_str(&rule.severity),
        rule.message.clone(),
        rule.effective_title().to_string(),
        rule.description.clone(),
        rule.id.clone(),
    );
    f.id = Uuid::new_v4();
    f.recommendations = rule.recommendations.clone();
    f.references = rule.references.clone();
    f.tags = rule.tags.clone();
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretlens_core::{AnalyzerKind, RuleConditions};

    fn make_ast_rule(id: &str, lang: &str, pattern: &str) -> Rule {
        Rule {
            id: id.to_string(),
            name: format!("AST rule {}", id),
            finding_type: "security".to_string(),
            severity: "critical".to_string(),
            language: lang.to_string(),
            analyzer: AnalyzerKind::Ast,
            pattern: pattern.to_string(),
            message: "Dangerous function detected".to_string(),
            title: String::new(),
            description: String::new(),
            redact: false,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![],
            references: vec![],
            tags: vec![],
            conditions: RuleConditions::default(),
        }
    }

    #[test]
    fn detects_python_eval() {
        let file = FileChange {
            file_path: "app.py".to_string(),
            content: "result = eval(user_input)\n".to_string(),
        };
        let line_table = file.build_line_table();
        let rule = make_ast_rule("AST-PY-001", "python", "call:eval");
        let findings = AstAnalyzer::analyze(&file, &[rule], &line_table);
        assert_eq!(findings.len(), 1, "Expected 1 finding: {:?}", findings);
        assert_eq!(findings[0].rule_id, "AST-PY-001");
    }

    #[test]
    fn detects_python_exec() {
        let file = FileChange {
            file_path: "app.py".to_string(),
            content: "exec(code)\n".to_string(),
        };
        let line_table = file.build_line_table();
        let rule = make_ast_rule("AST-PY-002", "python", "call:exec");
        let findings = AstAnalyzer::analyze(&file, &[rule], &line_table);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detects_js_eval() {
        let file = FileChange {
            file_path: "app.js".to_string(),
            content: "const x = eval(userInput);\n".to_string(),
        };
        let line_table = file.build_line_table();
        let rule = make_ast_rule("AST-JS-001", "javascript", "call:eval");
        let findings = AstAnalyzer::analyze(&file, &[rule], &line_table);
        assert_eq!(findings.len(), 1, "Expected 1 finding");
    }

    #[test]
    fn detects_js_weak_crypto_md5() {
        let file = FileChange {
            file_path: "app.js".to_string(),
            content: r#"const hash = crypto.createHash("md5");"#.to_string(),
        };
        let line_table = file.build_line_table();
        let rule = make_ast_rule("AST-JS-002", "javascript", "crypto_weak:md5");
        let findings = AstAnalyzer::analyze(&file, &[rule], &line_table);
        assert_eq!(findings.len(), 1, "Expected 1 finding for md5");
    }

    #[test]
    fn no_findings_for_safe_code() {
        let file = FileChange {
            file_path: "app.py".to_string(),
            content: "x = 1 + 2\nprint(x)\n".to_string(),
        };
        let line_table = file.build_line_table();
        let rule = make_ast_rule("AST-PY-001", "python", "call:eval");
        let findings = AstAnalyzer::analyze(&file, &[rule], &line_table);
        assert!(findings.is_empty());
    }
}
