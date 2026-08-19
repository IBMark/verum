use verum_nucleus::{Finding, Ir};

/// The K8s/Dockerfile/Terraform parsers emit findings during the Atlas mapping
/// phase; this just forwards them into the Prism result.
pub fn analyse(ir: &Ir) -> Vec<Finding> {
    ir.infra_findings.clone()
}
