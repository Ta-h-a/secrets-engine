use secretlens_core::Rule;
use std::collections::HashMap;

/// A deduplication registry for loaded rules, keyed by rule ID.
/// Ensures each rule ID appears exactly once.
pub struct RuleRegistry {
    rules: HashMap<String, Rule>,
    order: Vec<String>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            order: Vec::new(),
        }
    }

    /// Insert a rule. Returns false and does nothing if the ID already exists.
    pub fn insert(&mut self, rule: Rule) -> bool {
        if self.rules.contains_key(&rule.id) {
            return false;
        }
        self.order.push(rule.id.clone());
        self.rules.insert(rule.id.clone(), rule);
        true
    }

    /// Get a rule by ID
    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.rules.get(id)
    }

    /// Return all rules in insertion order
    pub fn all(&self) -> Vec<&Rule> {
        self.order
            .iter()
            .filter_map(|id| self.rules.get(id))
            .collect()
    }

    /// Return all rules as owned, in insertion order
    pub fn into_vec(mut self) -> Vec<Rule> {
        self.order
            .into_iter()
            .filter_map(|id| self.rules.remove(&id))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<Rule>> for RuleRegistry {
    fn from(rules: Vec<Rule>) -> Self {
        let mut registry = Self::new();
        for rule in rules {
            registry.insert(rule);
        }
        registry
    }
}
