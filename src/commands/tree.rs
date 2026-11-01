//! `tree` command implementation.

use super::{Ctx, HashMap, HashSet, Path, deserialize, output, read_input};

struct TreeNode {
    name: String,
    version: String,
    dep_type: Option<String>,
    dependencies: Vec<TreeNode>,
}

impl TreeNode {
    fn to_json(&self) -> serde_json::Value {
        let deps: Vec<serde_json::Value> =
            self.dependencies.iter().map(TreeNode::to_json).collect();
        let mut obj = serde_json::json!({
            "name": self.name,
            "version": self.version,
        });
        if let Some(ref dt) = self.dep_type {
            obj["dep_type"] = serde_json::Value::String(dt.clone());
        }
        obj["dependencies"] = serde_json::Value::Array(deps);
        obj
    }
}

/// Version string `x.y.z` for `name` via the prebuilt index (O(1)).
fn version_of(lockfile: &hlock::Lockfile, index: &HashMap<&str, usize>, name: &str) -> String {
    index
        .get(name)
        .and_then(|&i| lockfile.packages.get(i))
        .map_or_else(String::new, |p| {
            p.version_string()
                .split('@')
                .nth(1)
                .unwrap_or_default()
                .to_string()
        })
}

fn build_tree(
    lockfile: &hlock::Lockfile,
    index: &HashMap<&str, usize>,
    name: &str,
    current_depth: u32,
    max_depth: Option<u32>,
    dep_type_filter: &str,
    visited: &mut HashSet<String>,
) -> TreeNode {
    let pkg = lockfile.find_package(name);
    let mut node = TreeNode {
        name: name.to_string(),
        version: pkg
            .map(|p| {
                p.version_string()
                    .split('@')
                    .nth(1)
                    .unwrap_or_default()
                    .to_string()
            })
            .unwrap_or_default(),
        dep_type: None,
        dependencies: Vec::new(),
    };

    if max_depth.is_some_and(|max| current_depth >= max) {
        return node;
    }

    if visited.contains(name) {
        return node;
    }
    visited.insert(name.to_string());

    if let Some(pkg) = pkg {
        for dep in &pkg.dependencies {
            let follows = match dep_type_filter {
                "runtime" => matches!(dep.dep_type, hlock::DepType::Runtime),
                "dev" => matches!(dep.dep_type, hlock::DepType::Dev),
                "peer" => matches!(dep.dep_type, hlock::DepType::Peer),
                _ => true,
            };
            if !follows {
                continue;
            }

            let dt = dep.dep_type.as_str();
            if visited.contains(&dep.name) {
                node.dependencies.push(TreeNode {
                    name: format!("{} ↻", dep.name),
                    version: version_of(lockfile, index, &dep.name),
                    dep_type: Some(dt.to_string()),
                    dependencies: Vec::new(),
                });
                continue;
            }

            let mut child = build_tree(
                lockfile,
                index,
                &dep.name,
                current_depth + 1,
                max_depth,
                dep_type_filter,
                visited,
            );
            child.dep_type = Some(dt.to_string());
            node.dependencies.push(child);
        }
    }

    visited.remove(name);
    node
}

fn render_tree_text(node: &TreeNode, prefix: &str, is_last: bool, show_dep_type: bool) {
    let connector = if is_last { "└" } else { "├" };
    let is_cycle = node.name.contains(" ↻");
    let display_name = if is_cycle {
        node.name.clone()
    } else {
        format!("{}@{}", node.name, node.version)
    };
    let type_suffix = if show_dep_type {
        node.dep_type
            .as_ref()
            .map_or(String::new(), |dt| format!(" ({dt})"))
    } else {
        String::new()
    };
    println!("{prefix}{connector}── {display_name}{type_suffix}");

    let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
    let dep_count = node.dependencies.len();
    for (i, child) in node.dependencies.iter().enumerate() {
        let is_last_child = i == dep_count - 1;
        render_tree_text(child, &child_prefix, is_last_child, show_dep_type);
    }
}

/// Runs the `tree` command.
pub(crate) fn run(
    file: &Path,
    root: &[String],
    depth: Option<u32>,
    dep_type: &str,
    format: &str,
    ctx: Ctx,
) {
    let Ctx { quiet, .. } = ctx;

    let content = match read_input(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", file.display(), e);
            std::process::exit(2);
        }
    };
    let lockfile = match deserialize(&content) {
        Ok(lf) => lf,
        Err(e) => {
            eprintln!("[{}] Parse error: {}", e.error_code(), e);
            std::process::exit(2);
        }
    };

    let fmt = output::parse_format(format);
    let max_depth = depth;
    let filter_dep_type = dep_type;
    let index = lockfile.package_index();
    let root_names = root;

    if fmt == output::OutputFormat::Json {
        let mut trees = Vec::new();
        for root_name in root_names {
            let mut visited = HashSet::new();
            let tree = build_tree(
                &lockfile,
                &index,
                root_name,
                0,
                max_depth,
                filter_dep_type,
                &mut visited,
            );
            trees.push(tree);
        }

        let root_version = root_names
            .first()
            .map_or_else(String::new, |rn| version_of(&lockfile, &index, rn));

        let json = if root_names.len() == 1 {
            serde_json::json!({
                "root": root_names[0],
                "root_version": root_version,
                "tree": trees[0].to_json(),
            })
        } else {
            serde_json::json!({
                "roots": root_names,
                "trees": trees.iter().map(TreeNode::to_json).collect::<Vec<_>>(),
            })
        };
        if !quiet {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
    } else if !quiet {
        for (i, root_name) in root_names.iter().enumerate() {
            if root_names.len() > 1 && i > 0 {
                println!();
            }
            let mut visited = HashSet::new();
            let tree = build_tree(
                &lockfile,
                &index,
                root_name,
                0,
                max_depth,
                filter_dep_type,
                &mut visited,
            );
            let show_dep_type = filter_dep_type == "all";
            println!("{}@{}", tree.name, tree.version);
            let dep_count = tree.dependencies.len();
            for (j, child) in tree.dependencies.iter().enumerate() {
                let is_last = j == dep_count - 1;
                render_tree_text(child, "", is_last, show_dep_type);
            }
        }
    }
}
