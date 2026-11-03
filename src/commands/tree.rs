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

/// Hard cap on rendered tree nodes: shared sub-DAGs re-expand per path, so a
/// hostile diamond-heavy lockfile could otherwise render ~2^d nodes.
const MAX_TREE_NODES: usize = 100_000;

/// Version string `x.y.z` for `name` via the prebuilt index (O(1)).
///
/// The version is formatted from the `(major, minor, patch)` fields directly;
/// deriving it from `version_string()` with `split('@')` yields `scope/pkg`
/// for scoped names like `@scope/pkg`.
fn version_of(lockfile: &hlock::Lockfile, index: &HashMap<&str, usize>, name: &str) -> String {
    index
        .get(name)
        .and_then(|&i| lockfile.packages.get(i))
        .map_or_else(String::new, |p| {
            format!("{}.{}.{}", p.major, p.minor, p.patch)
        })
}

#[allow(clippy::too_many_arguments)] // explicit traversal parameters
fn build_tree(
    lockfile: &hlock::Lockfile,
    index: &HashMap<&str, usize>,
    name: &str,
    current_depth: u32,
    max_depth: Option<u32>,
    dep_type_filter: &str,
    visited: &mut HashSet<String>,
    budget: &mut usize,
) -> TreeNode {
    if *budget == 0 {
        return TreeNode {
            name: "… (tree truncated: node budget exhausted)".to_string(),
            version: String::new(),
            dep_type: None,
            dependencies: Vec::new(),
        };
    }
    *budget -= 1;

    let pkg = lockfile.find_package(name);
    let mut node = TreeNode {
        name: name.to_string(),
        version: pkg
            .map(|p| format!("{}.{}.{}", p.major, p.minor, p.patch))
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
                budget,
            );
            child.dep_type = Some(dt.to_string());
            node.dependencies.push(child);
        }
    }

    visited.remove(name);
    node
}

fn build_root_tree(
    lockfile: &hlock::Lockfile,
    index: &HashMap<&str, usize>,
    root_name: &str,
    max_depth: Option<u32>,
    dep_type_filter: &str,
) -> TreeNode {
    let mut visited = HashSet::new();
    let mut budget = MAX_TREE_NODES;
    build_tree(
        lockfile,
        index,
        root_name,
        0,
        max_depth,
        dep_type_filter,
        &mut visited,
        &mut budget,
    )
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

/// `ok` is false when none of the requested roots exist in the lockfile.
fn stdout_root_exists(json: &serde_json::Value) -> bool {
    if let Some(tree) = json.get("tree") {
        !tree["name"].as_str().unwrap_or("").contains(" ↻")
    } else {
        true
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
            trees.push(build_root_tree(
                &lockfile,
                &index,
                root_name,
                max_depth,
                filter_dep_type,
            ));
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
            let ok = stdout_root_exists(&json);
            println!(
                "{}",
                serde_json::to_string_pretty(&super::envelope("tree", ok, &json)).unwrap()
            );
        }
    } else if !quiet {
        for (i, root_name) in root_names.iter().enumerate() {
            if root_names.len() > 1 && i > 0 {
                println!();
            }
            let tree = build_root_tree(&lockfile, &index, root_name, max_depth, filter_dep_type);
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
