use std::path::Path;

use verum_nucleus::Framework;

/// Detect the framework used in the project by reading composer.json.
pub fn detect_framework(root: &Path) -> Framework {
    let composer_path = root.join("composer.json");

    if !composer_path.exists() {
        return Framework::Unknown;
    }

    let content = match std::fs::read_to_string(&composer_path) {
        Ok(c) => c,
        Err(_) => return Framework::Unknown,
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Framework::Unknown,
    };

    if let Some(require) = json.get("require").and_then(|r| r.as_object()) {
        if require.contains_key("laravel/framework") {
            return Framework::Laravel;
        }
        if require.contains_key("symfony/framework-bundle")
            || require.contains_key("symfony/symfony")
        {
            return Framework::Symfony;
        }
    }

    if root.join("wp-config.php").exists() || root.join("wp-content").exists() {
        return Framework::WordPress;
    }

    Framework::Unknown
}
