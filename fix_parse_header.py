import sys

with open('src/lockfile.rs', 'r') as f:
    content = f.read()

# Define the old function signature and find its extent
old_start = content.find('fn parse_header(content: &str) -> Result<(Lockfile, &str), Error> {')
if old_start == -1:
    print("parse_header not found")
    sys.exit(1)
# Find the matching closing brace by scanning
brace_count = 1
i = content.find('{', old_start) + 1
while i < len(content) and brace_count > 0:
    if content[i] == '{':
        brace_count += 1
    elif content[i] == '}':
        brace_count -= 1
    i += 1
old_end = i

old_func = content[old_start:old_end]

new_func = '''fn parse_header(content: &str) -> Result<(Lockfile, &str), Error> {
    let mut sources = Vec::new();
    let mut overrides = Vec::new();
    let mut features = vec![];
    let mut metadata = vec![];
    let mut workspace_root = None;
    let mut workspace_pkgs = Vec::new();
    let mut hoist_boundaries = Vec::new();
    let lines = content.lines().enumerate();

    for (line_num, line) in lines {
        if line.is_empty() {
            let header_end = content.find("\\n\\n").map(|i| i + 2).unwrap_or(content.len());
            let remaining = &content[header_end..];
            return Ok((Lockfile {
                sources,
                overrides,
                features,
                metadata,
                workspace_root,
                workspace_pkgs,
                hoist_boundaries,
                packages: vec![],
                artifacts: vec![],
                patches: vec![],
                provenance: vec![],
                advisories: vec![],
                licenses: vec![],
                policies: vec![],
                trust_roots: vec![],
                mirrors: vec![],
                compat: None,
            }, remaining));
        }

        if let Some(rest) = line.strip_prefix("@source ") {
            let mut parts = rest.splitn(2, ' ');
            let idx_str = parts.next().ok_or_else(|| Error::InvalidHeader { line_number: line_num, reason: "Missing source index".to_string() })?;
            let idx: usize = idx_str.parse().map_err(|_| Error::InvalidHeader { line_number: line_num, reason: "Invalid source index".to_string() })?;
            let val = parts.next().ok_or_else(|| Error::InvalidHeader { line_number: line_num, reason: "Missing source value".to_string() })?;
            let source = if val == "workspace" {
                Source::Workspace
            } else if val.starts_with("file://") || val.starts_with('/') {
                Source::Local(val.to_string())
            } else if val.starts_with("git://") || (val.starts_with("https://") && val.contains(".git")) {
                Source::Git(val.to_string())
            } else if val.starts_with("cas+http://") || val.starts_with("cas+https://") {
                Source::CasHttp(val.strip_prefix("cas+").unwrap_or(val).to_string())
            } else if val.starts_with("ipfs://") {
                Source::Ipfs(val.to_string())
            } else {
                Source::Registry(val.to_string())
            };
            if idx != sources.len() {
                return Err(Error::InvalidHeader { line_number: line_num, reason: format!("Source index {} is out of order", idx) });
            }
            sources.push(source);
        } else if let Some(rest) = line.strip_prefix("@override ") {
            let mut parts = rest.split(" -> ");
            let left = parts.next().unwrap_or("");
            let to_ver = parts.next().ok_or_else(|| Error::InvalidHeader { line_number: line_num, reason: "Missing '->' in override".to_string() })?;
            let mut left_parts = left.splitn(2, ' ');
            let name = left_parts.next().unwrap_or("").to_string();
            let from_ver = left_parts.next().unwrap_or("").to_string();
            overrides.push(Override { name, from_version: from_ver, ty: DepType::Runtime, to_version: to_ver.to_string() });
        } else if let Some(rest) = line.strip_prefix("@feature ") {
            let mut parts = rest.splitn(2, ' ');
            let name = parts.next().unwrap_or("").to_string();
            let flags_str = parts.next().unwrap_or("").to_string();
            let flags = if flags_str.is_empty() { vec![] } else { flags_str.split(',').map(|s| s.trim().to_string()).collect() };
            features.push((name, flags));
        } else if let Some(rest) = line.strip_prefix("@workspace-root ") {
            workspace_root = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("@workspace-pkg ") {
            let (name, manifest_path) = rest.split_once(' ').unwrap_or((rest, ""));
            workspace_pkgs.push(WorkspacePkg { name: name.to_string(), manifest_path: manifest_path.to_string() });
        } else if let Some(rest) = line.strip_prefix("@hoist-boundary ") {
            let mut parts = rest.splitn(2, "->");
            let cosine = parts.next().unwrap_or("").trim().to_string();
            let deps_str = parts.next().unwrap_or("").trim();
            let deps_str = deps_str.strip_prefix("[").unwrap_or(deps_str);
            let deps_str = deps_str.strip_suffix("]").unwrap_or(deps_str);
            let allowed_deps = if deps_str.is_empty() { vec![] } else { deps_str.split(',').map(|s| s.trim().to_string()).collect() };
            hoist_boundaries.push(HoistBoundary { cosine, allowed_deps });
        } else if let Some(rest) = line.strip_prefix("@metadata ") {
            let (key, value) = rest.split_once(' ').unwrap_or((rest, ""));
            metadata.push((key.to_string(), value.to_string()));
        } else {
            return Err(Error::InvalidHeader { line_number: line_num, reason: format!("Unknown directive: {}", line) });
        }
    }

    Err(Error::InvalidHeader { line_number: 0, reason: "Missing empty line separator after header".to_string() })
}'''

content = content[:old_start] + new_func + content[old_end:]
with open('src/lockfile.rs', 'w') as f:
    f.write(content)
print("parse_header replaced")
