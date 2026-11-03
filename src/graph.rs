//! Cached dependency graph over a [`Lockfile`] (v1.0).
//!
//! 0.x exposed free functions that rebuilt a name→index map (and often a
//! reverse-adjacency map) on **every call**, resolved dependency edges by
//! linear scans (`dependency_cid` walked the whole cid map per edge), and
//! detected cycles with unbounded recursion. That made `extract_subgraph`
//! ~O(n³) and `stats` O(n²).
//!
//! 1.0 builds one CSR adjacency (forward + reverse) in O(V+E) and answers all
//! queries from it. Cycle detection is iterative (no stack overflow on deep
//! chains), `has_dep_path` exits early, and `reachability` memoizes transitive
//! closures as bitsets via Tarjan SCC condensation.

use crate::cid;
use crate::error::Error;
use crate::lockfile::{
    DepType, Dependency, Lockfile, LockfileDiff, Package, PackageChange, PlatformTag, TargetArch,
    TargetOS,
};
use std::collections::{BTreeSet, HashMap, HashSet};

/// How to filter dependency edges in traversal queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeFilter {
    /// Follow only `Runtime` edges.
    Runtime,
    /// Follow only `Dev` edges.
    Dev,
    /// Follow only `Peer` edges.
    Peer,
    /// Follow only `Optional` / `OptionalTarget` edges.
    Optional,
    /// Follow every edge.
    All,
}

impl EdgeFilter {
    /// True when `dep`'s type passes this filter.
    ///
    /// 0.x silently returned `false` for `Peer`/`Optional` queries, making
    /// `--dep-type peer` a no-op; 1.0 matches every declared kind.
    #[must_use]
    pub fn matches(self, dep: &Dependency) -> bool {
        match self {
            Self::Runtime => dep.dep_type == DepType::Runtime,
            Self::Dev => dep.dep_type == DepType::Dev,
            Self::Peer => dep.dep_type == DepType::Peer,
            Self::Optional => matches!(
                dep.dep_type,
                DepType::Optional | DepType::OptionalTarget(_, _)
            ),
            Self::All => true,
        }
    }

    /// The filter corresponding to a plain [`DepType`] query (0.x semantics
    /// for the `runtime`/`dev` cases).
    #[must_use]
    pub fn from_dep_type(ty: DepType) -> Self {
        match ty {
            DepType::Runtime => Self::Runtime,
            DepType::Dev => Self::Dev,
            DepType::Peer => Self::Peer,
            DepType::Optional | DepType::OptionalTarget(_, _) => Self::Optional,
        }
    }
}

/// Cached dependency graph: name index + cid map + CSR forward/reverse adjacency.
pub struct Graph<'a> {
    lockfile: &'a Lockfile,
    name_to_idx: HashMap<&'a str, usize>,
    /// Content id → package index (collision-checked at construction).
    cid_to_idx: HashMap<u64, usize>,
    /// CSR forward adjacency: `fwd_targets[fwd_offsets[i]..fwd_offsets[i+1]]`
    /// are the dependency targets of package `i` (parallel to `fwd_kinds`).
    fwd_offsets: Vec<u32>,
    fwd_targets: Vec<u32>,
    fwd_kinds: Vec<u8>,
    /// CSR reverse adjacency: packages that depend on `i`.
    rev_offsets: Vec<u32>,
    rev_sources: Vec<u32>,
}

impl<'a> Graph<'a> {
    /// Builds the graph in O(V+E), rejecting content-id collisions.
    ///
    /// # Errors
    /// Returns [`Error::ContentIdCollision`] when two distinct
    /// `(name, version)` identities share a 64-bit content id.
    #[allow(clippy::cast_possible_truncation)] // CSR u32 indices, see below
    pub fn new(lockfile: &'a Lockfile) -> Result<Self, Error> {
        let n = lockfile.packages.len();
        let mut name_to_idx: HashMap<&'a str, usize> = HashMap::with_capacity(n);
        let mut cid_to_idx: HashMap<u64, usize> = HashMap::with_capacity(n);
        let mut cid_seen: HashMap<u64, (String, u64, u64, u64)> = HashMap::with_capacity(n);

        for (idx, pkg) in lockfile.packages.iter().enumerate() {
            if name_to_idx.insert(pkg.name.as_str(), idx).is_some() {
                // Multiple versions of the same name are allowed; the index
                // keeps the first (canonical order is name-sorted, stable).
            }
            let cid = cid::package_cid(pkg);
            let identity = (pkg.name.clone(), pkg.major, pkg.minor, pkg.patch);
            if let Some(first) = cid_seen.get(&cid)
                && (first.0 != identity.0
                    || first.1 != identity.1
                    || first.2 != identity.2
                    || first.3 != identity.3)
            {
                return Err(Error::ContentIdCollision(format!(
                    "{}@{}.{}.{} and {}@{}.{}.{} share content id {cid:016x}",
                    first.0,
                    first.1,
                    first.2,
                    first.3,
                    identity.0,
                    identity.1,
                    identity.2,
                    identity.3
                )));
            }
            cid_seen.insert(cid, identity);
            cid_to_idx.insert(cid, idx);
        }

        // Pass 1: count edges to size the CSR arrays.
        let mut edge_count = 0usize;
        for pkg in &lockfile.packages {
            for dep in &pkg.dependencies {
                if name_to_idx.contains_key(dep.name.as_str()) {
                    edge_count += 1;
                }
            }
        }

        // CSR indices are u32: a 4-billion-package lockfile cannot be held in
        // memory anyway, so the casts below are lossless for any real input.
        let mut fwd_offsets = Vec::with_capacity(n + 1);
        let mut fwd_targets = Vec::with_capacity(edge_count);
        let mut fwd_kinds = Vec::with_capacity(edge_count);
        let mut rev_counts = vec![0u32; n + 1];

        fwd_offsets.push(0u32);
        for pkg in &lockfile.packages {
            for dep in &pkg.dependencies {
                if let Some(&target) = name_to_idx.get(dep.name.as_str()) {
                    fwd_targets.push(target as u32);
                    fwd_kinds.push(dep.dep_type.id());
                    rev_counts[target + 1] += 1;
                }
            }
            let last = fwd_offsets.last().copied().unwrap_or_default();
            fwd_offsets.push(last + (fwd_targets.len() as u32 - last));
        }

        // Prefix-sum reverse offsets.
        let mut rev_offsets = Vec::with_capacity(n + 1);
        let mut acc = 0u32;
        rev_offsets.push(0);
        for count in &rev_counts[1..] {
            acc += *count;
            rev_offsets.push(acc);
        }
        let mut rev_sources = vec![0u32; edge_count];
        let mut rev_fill = rev_offsets.clone();
        for (i, pkg) in lockfile.packages.iter().enumerate() {
            for dep in &pkg.dependencies {
                if let Some(&target) = name_to_idx.get(dep.name.as_str()) {
                    let slot = rev_fill[target] as usize;
                    rev_sources[slot] = i as u32;
                    rev_fill[target] += 1;
                }
            }
        }

        Ok(Self {
            lockfile,
            name_to_idx,
            cid_to_idx,
            fwd_offsets,
            fwd_targets,
            fwd_kinds,
            rev_offsets,
            rev_sources,
        })
    }

    /// The underlying lockfile.
    #[must_use]
    pub const fn lockfile(&self) -> &'a Lockfile {
        self.lockfile
    }

    /// Number of packages.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lockfile.packages.len()
    }

    /// True when the graph has no packages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lockfile.packages.is_empty()
    }

    /// Package at index `idx`.
    #[must_use]
    pub fn package(&self, idx: usize) -> &'a Package {
        &self.lockfile.packages[idx]
    }

    /// All packages, in lockfile order.
    #[must_use]
    pub fn packages(&self) -> &'a [Package] {
        &self.lockfile.packages
    }

    /// Index of `name` (first occurrence for multi-version lockfiles).
    #[must_use]
    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.name_to_idx.get(name).copied()
    }

    /// Name of the package at index `idx`.
    #[must_use]
    pub fn name_of(&self, idx: usize) -> &'a str {
        &self.lockfile.packages[idx].name
    }

    /// Index for a content id.
    #[must_use]
    pub fn index_of_cid(&self, content_id: u64) -> Option<usize> {
        self.cid_to_idx.get(&content_id).copied()
    }

    /// Content id of the package at index `idx`.
    #[must_use]
    pub fn cid_of(&self, idx: usize) -> u64 {
        cid::package_cid(&self.lockfile.packages[idx])
    }

    /// Resolves a dependency name the way the wire format does: the first
    /// package with that name, by its own version. 0.x walked the whole cid
    /// map's values per edge; this is one hash lookup.
    #[must_use]
    pub fn resolve_dep_cid(&self, dep_name: &str) -> Option<u64> {
        let idx = self.index_of(dep_name)?;
        Some(self.cid_of(idx))
    }

    /// Direct dependency indices of package `idx` passing `filter`.
    fn deps_of(&self, idx: usize, filter: EdgeFilter) -> impl Iterator<Item = usize> + '_ {
        let start = self.fwd_offsets[idx] as usize;
        let end = self.fwd_offsets[idx + 1] as usize;
        (start..end).filter_map(move |slot| {
            let dep_type = DepType::from_id(self.fwd_kinds[slot]);
            let dep_matches = match filter {
                EdgeFilter::All => true,
                _ => filter.matches(&Dependency {
                    name: String::new(),
                    dep_type,
                    requested_features: Vec::new(),
                }),
            };
            dep_matches.then(|| self.fwd_targets[slot] as usize)
        })
    }

    /// Direct dependent indices of package `idx` passing `filter`.
    fn dependents_of_idx(&self, idx: usize, filter: EdgeFilter) -> Vec<usize> {
        let start = self.rev_offsets[idx] as usize;
        let end = self.rev_offsets[idx + 1] as usize;
        let mut out = Vec::new();
        for &src in &self.rev_sources[start..end] {
            let src = src as usize;
            if filter == EdgeFilter::All
                || self.lockfile.packages[src]
                    .dependencies
                    .iter()
                    .any(|d| d.name == self.lockfile.packages[idx].name && filter.matches(d))
            {
                out.push(src);
            }
        }
        out
    }

    /// Packages nothing depends on (roots of the reverse graph), sorted by name.
    #[must_use]
    pub fn leaf_packages(&self) -> Vec<&'a Package> {
        let mut has_dependents = vec![false; self.len()];
        for pkg in &self.lockfile.packages {
            for dep in &pkg.dependencies {
                if let Some(&dep_idx) = self.name_to_idx.get(dep.name.as_str()) {
                    has_dependents[dep_idx] = true;
                }
            }
        }
        let mut leaves: Vec<&'a Package> = self
            .lockfile
            .packages
            .iter()
            .enumerate()
            .filter(|(i, _)| !has_dependents[*i])
            .map(|(_, p)| p)
            .collect();
        leaves.sort_by_key(|p| &p.name);
        leaves
    }

    /// Count of direct dependencies of `name` matching `dep_type`.
    #[must_use]
    pub fn dep_count(&self, name: &str, dep_type: DepType) -> usize {
        let Some(&idx) = self.name_to_idx.get(name) else {
            return 0;
        };
        self.lockfile.packages[idx]
            .dependencies
            .iter()
            .filter(|d| d.dep_type == dep_type)
            .count()
    }

    /// Transitive dependencies of `name` following every edge kind.
    #[must_use]
    pub fn transitive_deps(&self, name: &str) -> HashSet<String> {
        self.typed_transitive_deps(name, EdgeFilter::All)
    }

    /// Transitive runtime dependencies of `name`.
    #[must_use]
    pub fn runtime_deps(&self, name: &str) -> HashSet<String> {
        self.typed_transitive_deps(name, EdgeFilter::Runtime)
    }

    /// Transitive dev dependencies of `name`.
    #[must_use]
    pub fn dev_deps(&self, name: &str) -> HashSet<String> {
        self.typed_transitive_deps(name, EdgeFilter::Dev)
    }

    /// Transitive dependencies of `name` following only `filter` edges.
    #[must_use]
    pub fn typed_transitive_deps(&self, name: &str, filter: EdgeFilter) -> HashSet<String> {
        let Some(start) = self.index_of(name) else {
            return HashSet::new();
        };
        let visited = self.reachable_from(start, filter);
        visited
            .into_iter()
            .filter(|&i| i != start)
            .map(|i| self.lockfile.packages[i].name.clone())
            .collect()
    }

    /// Indices reachable from `start` via `filter` edges (BFS, iterative).
    fn reachable_from(&self, start: usize, filter: EdgeFilter) -> Vec<usize> {
        let mut visited = vec![false; self.len()];
        visited[start] = true;
        let mut stack = vec![start];
        let mut out = Vec::new();
        while let Some(idx) = stack.pop() {
            for dep in self.deps_of(idx, filter) {
                if !visited[dep] {
                    visited[dep] = true;
                    stack.push(dep);
                    out.push(dep);
                }
            }
        }
        out
    }

    /// Packages that (transitively) depend on `name`, any edge kind.
    #[must_use]
    pub fn dependents_of(&self, name: &str) -> Vec<String> {
        self.typed_dependents_of(name, EdgeFilter::All)
    }

    /// Packages that (transitively) runtime-depend on `name`.
    #[must_use]
    pub fn runtime_dependents_of(&self, name: &str) -> Vec<String> {
        self.typed_dependents_of(name, EdgeFilter::Runtime)
    }

    /// Packages that (transitively) dev-depend on `name`.
    #[must_use]
    pub fn dev_dependents_of(&self, name: &str) -> Vec<String> {
        self.typed_dependents_of(name, EdgeFilter::Dev)
    }

    /// Packages that (transitively) depend on `name` via `filter` edges.
    #[must_use]
    pub fn typed_dependents_of(&self, name: &str, filter: EdgeFilter) -> Vec<String> {
        let Some(start) = self.index_of(name) else {
            return Vec::new();
        };
        let mut visited = vec![false; self.len()];
        visited[start] = true;
        let mut stack = vec![start];
        let mut result = Vec::new();
        while let Some(idx) = stack.pop() {
            for parent in self.dependents_of_idx(idx, filter) {
                if !visited[parent] {
                    visited[parent] = true;
                    stack.push(parent);
                    result.push(self.lockfile.packages[parent].name.clone());
                }
            }
        }
        result.sort();
        result
    }

    /// True when a dependency path `from → to` exists following `filter`.
    ///
    /// Early-exits on the first hit instead of computing the full reachable
    /// set (0.x behavior).
    #[must_use]
    pub fn has_dep_path(&self, from: &str, to: &str, filter: EdgeFilter) -> bool {
        if from == to {
            return self.name_to_idx.contains_key(from);
        }
        let (Some(start), Some(target)) = (self.index_of(from), self.index_of(to)) else {
            return false;
        };
        let mut visited = vec![false; self.len()];
        visited[start] = true;
        let mut stack = vec![start];
        while let Some(idx) = stack.pop() {
            for dep in self.deps_of(idx, filter) {
                if dep == target {
                    return true;
                }
                if !visited[dep] {
                    visited[dep] = true;
                    stack.push(dep);
                }
            }
        }
        false
    }

    /// True when adding `new_deps` to `package_name` would create a cycle.
    #[must_use]
    pub fn would_create_cycle(&self, package_name: &str, new_deps: &[String]) -> bool {
        let Some(start) = self.index_of(package_name) else {
            return false;
        };
        for new_dep in new_deps {
            if new_dep == package_name {
                return true;
            }
            let Some(dep_idx) = self.index_of(new_dep) else {
                continue;
            };
            if self.has_dep_path_idx(dep_idx, start) {
                return true;
            }
        }
        false
    }

    fn has_dep_path_idx(&self, from: usize, to: usize) -> bool {
        let mut visited = vec![false; self.len()];
        visited[from] = true;
        let mut stack = vec![from];
        while let Some(idx) = stack.pop() {
            if idx == to {
                return true;
            }
            for dep in self.deps_of(idx, EdgeFilter::All) {
                if !visited[dep] {
                    visited[dep] = true;
                    stack.push(dep);
                }
            }
        }
        false
    }

    /// Returns one cycle as package names in traversal order, if any exist.
    ///
    /// Iterative color-DFS: 0.x recursed once per chain link, which overflowed
    /// the stack on pathological (10k+) dependency chains.
    #[must_use]
    pub fn detect_cycle(&self) -> Option<Vec<String>> {
        const WHITE: u8 = 0;
        const GRAY: u8 = 1;
        const BLACK: u8 = 2;
        let n = self.len();
        let mut color = vec![WHITE; n];
        let mut parent: Vec<Option<usize>> = vec![None; n];

        for start in 0..n {
            if color[start] != WHITE {
                continue;
            }
            // Explicit DFS stack of (node, next-edge-slot).
            let mut stack: Vec<(usize, usize)> = vec![(start, self.fwd_offsets[start] as usize)];
            color[start] = GRAY;
            while let Some(&mut (idx, ref mut slot)) = stack.last_mut() {
                let end = self.fwd_offsets[idx + 1] as usize;
                if *slot >= end {
                    color[idx] = BLACK;
                    stack.pop();
                    continue;
                }
                let target = self.fwd_targets[*slot] as usize;
                *slot += 1;
                match color[target] {
                    WHITE => {
                        color[target] = GRAY;
                        parent[target] = Some(idx);
                        let next_slot = self.fwd_offsets[target] as usize;
                        stack.push((target, next_slot));
                    }
                    GRAY => {
                        // Reconstruct the cycle idx → ... → target.
                        let mut cycle = Vec::new();
                        let mut cur = Some(idx);
                        while let Some(c) = cur {
                            cycle.push(self.lockfile.packages[c].name.clone());
                            if c == target {
                                break;
                            }
                            cur = parent[c];
                        }
                        cycle.reverse();
                        return Some(cycle);
                    }
                    _ => {}
                }
            }
        }
        None
    }

    /// Kahn topological order (package indices, lexicographic tie-break).
    ///
    /// # Errors
    /// Returns the names of one detected cycle when the graph is cyclic.
    pub fn topological_sort(&self) -> Result<Vec<usize>, Vec<String>> {
        let n = self.len();
        // in_degree[i] = number of i's dependencies (packages must come after
        // everything they depend on; ties broken lexicographically).
        let mut in_degree = vec![0usize; n];
        let mut dependents_of_idx: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, pkg) in self.lockfile.packages.iter().enumerate() {
            for dep in &pkg.dependencies {
                if let Some(&dep_idx) = self.name_to_idx.get(dep.name.as_str()) {
                    in_degree[i] += 1;
                    dependents_of_idx[dep_idx].push(i);
                }
            }
        }
        let out_degree_of_deps = &dependents_of_idx;

        let mut ready: BTreeSet<&str> = BTreeSet::new();
        for (i, deg) in in_degree.iter().enumerate() {
            if *deg == 0 {
                ready.insert(self.lockfile.packages[i].name.as_str());
            }
        }

        let mut result = Vec::with_capacity(n);
        while let Some(name) = ready.pop_first() {
            let idx = self.name_to_idx[name];
            result.push(idx);
            for &dependent in &out_degree_of_deps[idx] {
                in_degree[dependent] -= 1;
                if in_degree[dependent] == 0 {
                    ready.insert(self.lockfile.packages[dependent].name.as_str());
                }
            }
        }

        if result.len() != n {
            if let Some(cycle) = self.detect_cycle() {
                return Err(cycle);
            }
            return Err(vec!["unknown cycle".to_string()]);
        }
        Ok(result)
    }

    /// All dependency paths from `package_name` to the graph roots (packages
    /// with no dependents), bounded by `max_paths`.
    #[must_use]
    pub fn all_paths_to_roots(&self, package_name: &str, max_paths: usize) -> Vec<Vec<String>> {
        let Some(start) = self.index_of(package_name) else {
            return Vec::new();
        };
        let mut all_paths = Vec::new();
        // Queue of (node, path-as-indices). Path membership checks are on
        // indices (O(depth)) instead of cloned name strings.
        let mut queue: Vec<(usize, Vec<usize>)> = vec![(start, vec![start])];
        while let Some((idx, path)) = queue.pop() {
            let parents = self.dependents_of_idx(idx, EdgeFilter::All);
            if parents.is_empty() {
                all_paths.push(
                    path.iter()
                        .rev()
                        .map(|&i| self.lockfile.packages[i].name.clone())
                        .collect(),
                );
                if all_paths.len() >= max_paths {
                    break;
                }
            } else {
                for &parent_idx in &parents {
                    if path.contains(&parent_idx) {
                        continue; // cycle guard
                    }
                    let mut new_path = path.clone();
                    new_path.push(parent_idx);
                    queue.push((parent_idx, new_path));
                }
            }
        }
        all_paths
    }

    /// Strongly connected components (Tarjan, iterative), plus the component
    /// reverse-topological order used by [`Self::reachability`].
    fn tarjan_scc(&self) -> (Vec<usize>, Vec<Vec<usize>>) {
        const UNVISITED: u32 = u32::MAX;
        let n = self.len();
        let mut index_of = vec![UNVISITED; n];
        let mut lowlink = vec![0u32; n];
        let mut on_stack = vec![false; n];
        let mut comp_of = vec![usize::MAX; n];
        let mut scc_index: u32 = 0;
        let mut stack: Vec<usize> = Vec::new();
        let mut components: Vec<Vec<usize>> = Vec::new();

        // Iterative Tarjan: stack of (node, next-slot).
        let mut call: Vec<(usize, usize)> = Vec::new();
        for root in 0..n {
            if index_of[root] != UNVISITED {
                continue;
            }
            index_of[root] = scc_index;
            lowlink[root] = scc_index;
            scc_index += 1;
            stack.push(root);
            on_stack[root] = true;
            call.push((root, self.fwd_offsets[root] as usize));

            while let Some(&mut (v, ref mut slot)) = call.last_mut() {
                let end = self.fwd_offsets[v + 1] as usize;
                if *slot < end {
                    let w = self.fwd_targets[*slot] as usize;
                    *slot += 1;
                    if index_of[w] == UNVISITED {
                        index_of[w] = scc_index;
                        lowlink[w] = scc_index;
                        scc_index += 1;
                        stack.push(w);
                        on_stack[w] = true;
                        call.push((w, self.fwd_offsets[w] as usize));
                    } else if on_stack[w] {
                        lowlink[v] = lowlink[v].min(index_of[w]);
                    }
                } else {
                    call.pop();
                    if let Some(&(parent_v, _)) = call.last() {
                        lowlink[parent_v] = lowlink[parent_v].min(lowlink[v]);
                    }
                    if lowlink[v] == index_of[v] {
                        let mut comp = Vec::new();
                        while let Some(w) = stack.pop() {
                            on_stack[w] = false;
                            comp_of[w] = components.len();
                            comp.push(w);
                            if w == v {
                                break;
                            }
                        }
                        components.push(comp);
                    }
                }
            }
        }
        (comp_of, components)
    }

    /// Memoized transitive closure as one bitset (row of `u64`s) per package.
    ///
    /// Computed once via SCC condensation + DP over the condensation DAG in
    /// O(V+E + V·V/64); 0.x rebuilt a full BFS per package (O(V·E) for
    /// `stats`). Rows include the package's own bit.
    ///
    /// # Errors
    /// Forwarded from [`Graph::new`] only — the closure itself is total.
    pub fn reachability(&self) -> Result<Reachability<'_, 'a>, Error> {
        let n = self.len();
        let words = n.div_ceil(64);
        let (comp_of, components) = self.tarjan_scc();
        let mut comp_masks = vec![vec![0u64; words]; components.len()];

        // Components are produced in reverse topological order of the
        // condensation (dependencies first), so unioning dependency component
        // masks as we go is a valid DP.
        for (comp_idx, comp) in components.iter().enumerate() {
            // Collect dependency component ids first so the mutable borrow of
            // this component's mask does not conflict with reading others.
            let mut dep_comps: Vec<usize> = Vec::new();
            for &node in comp {
                for dep in self.deps_of(node, EdgeFilter::All) {
                    let dep_comp = comp_of[dep];
                    if dep_comp != comp_idx {
                        dep_comps.push(dep_comp);
                    }
                }
            }
            // Take the mask out so dependency masks can be read freely.
            let mut mask = std::mem::take(&mut comp_masks[comp_idx]);
            for &node in comp {
                mask[node / 64] |= 1 << (node % 64);
            }
            for dep_comp in &dep_comps {
                let dep_mask = &comp_masks[*dep_comp];
                for (m, d) in mask.iter_mut().zip(dep_mask.iter()) {
                    *m |= *d;
                }
            }
            comp_masks[comp_idx] = mask;
        }

        Ok(Reachability {
            graph: self,
            comp_of,
            comp_masks,
        })
    }

    /// Extracts the subgraph reachable from `root_content_ids`, following all
    /// dependency edges (O(V+E); 0.x was a fixpoint loop over the whole
    /// package list with a linear cid resolution per edge, ~O(n³)).
    ///
    /// # Errors
    /// Returns [`Error::RootContentIdMissing`] when a root does not exist.
    pub fn extract_subgraph(&self, root_content_ids: &[u64]) -> Result<Lockfile, Error> {
        self.extract_inner(root_content_ids, None)
    }

    /// Extracts the subgraph reachable from the roots when traversing only
    /// packages whose platform tags match `target_os`/`target_arch`.
    ///
    /// # Errors
    /// Returns [`Error::RootContentIdMissing`] when a root does not exist and
    /// [`Error::NoPackagesForPlatform`] when nothing matches the platform.
    pub fn extract_subgraph_platform(
        &self,
        root_content_ids: &[u64],
        target_os: TargetOS,
        target_arch: TargetArch,
    ) -> Result<Lockfile, Error> {
        self.extract_inner(root_content_ids, Some((target_os, target_arch)))
    }

    fn extract_inner(
        &self,
        root_content_ids: &[u64],
        platform: Option<(TargetOS, TargetArch)>,
    ) -> Result<Lockfile, Error> {
        let mut roots = Vec::new();
        for root_id in root_content_ids {
            let Some(&idx) = self.cid_to_idx.get(root_id) else {
                return Err(Error::RootContentIdMissing {
                    content_id: *root_id,
                });
            };
            roots.push(idx);
        }

        let matches = |idx: usize| -> bool {
            match platform {
                None => true,
                Some((os, arch)) => {
                    let pkg = &self.lockfile.packages[idx];
                    pkg.platform_tags.is_empty()
                        || pkg
                            .platform_tags
                            .iter()
                            .any(|tag| platform_matches(tag, os, arch))
                }
            }
        };

        let mut output_indices = HashSet::new();
        let mut stack: Vec<usize> = roots.into_iter().filter(|&i| matches(i)).collect();
        for &i in &stack {
            output_indices.insert(i);
        }
        while let Some(idx) = stack.pop() {
            for dep in self.deps_of(idx, EdgeFilter::All) {
                if matches(dep) && output_indices.insert(dep) {
                    stack.push(dep);
                }
            }
        }

        if let Some((os, arch)) = platform.filter(|_| output_indices.is_empty()) {
            return Err(Error::NoPackagesForPlatform {
                os: format!("{os:?}"),
                arch: format!("{arch:?}"),
            });
        }

        let mut extracted_packages: Vec<Package> = output_indices
            .into_iter()
            .map(|i| self.lockfile.packages[i].clone())
            .collect();

        let subgraph_names: HashSet<&str> =
            extracted_packages.iter().map(|p| p.name.as_str()).collect();
        let filtered_provenance: Vec<crate::provenance::ResolutionProvenance> = self
            .lockfile
            .provenance
            .iter()
            .filter(|p| subgraph_names.contains(p.package_name.as_str()))
            .cloned()
            .collect();

        Ok(assemble_subgraph(
            self.lockfile,
            &mut extracted_packages,
            filtered_provenance,
        ))
    }

    /// Exports the dependency graph as a Graphviz DOT digraph.
    ///
    /// Node ids are stable indices (`n0`, `n1`, …) so duplicate
    /// `name@version` labels can no longer collide; labels stay
    /// `name@x.y.z`. Label text is escaped so hostile package names cannot
    /// inject DOT syntax.
    #[must_use]
    pub fn export_dot(&self) -> String {
        use std::fmt::Write as _;
        let escape = |s: &str| {
            let mut out = String::with_capacity(s.len());
            for c in s.chars() {
                match c {
                    '"' | '\\' => {
                        out.push('\\');
                        out.push(c);
                    }
                    '\n' | '\r' => out.push(' '),
                    _ => out.push(c),
                }
            }
            out
        };
        let mut out = String::with_capacity(self.len() * 48 + 64);
        out.push_str("digraph dependencies {\n");
        out.push_str("  rankdir=LR;\n");
        out.push_str("  node [shape=box, style=rounded, fontname=\"Helvetica\"];\n");
        for (i, pkg) in self.lockfile.packages.iter().enumerate() {
            let _ = writeln!(out, "  n{i} [label=\"{}\"];", escape(&pkg.version_string()));
        }
        for (i, pkg) in self.lockfile.packages.iter().enumerate() {
            for dep in &pkg.dependencies {
                let style = match dep.dep_type {
                    DepType::Runtime => "",
                    DepType::Dev => ", style=dashed",
                    DepType::Peer => ", style=bold",
                    DepType::Optional | DepType::OptionalTarget(_, _) => ", style=dotted",
                };
                let target = self.name_to_idx.get(dep.name.as_str()).map_or_else(
                    || format!("\"{}\"", escape(&dep.name)),
                    |&t| format!("n{t}"),
                );
                let _ = writeln!(
                    out,
                    "  n{i} -> {target} [label=\"{}\"{style}];",
                    escape(dep.dep_type.as_str())
                );
            }
        }
        out.push_str("}\n");
        out
    }
}

/// Memoized transitive closure produced by [`Graph::reachability`].
pub struct Reachability<'g, 'a> {
    graph: &'g Graph<'a>,
    comp_of: Vec<usize>,
    comp_masks: Vec<Vec<u64>>,
}

impl Reachability<'_, '_> {
    /// All packages transitively reachable from `idx` (excluding itself),
    /// as indices in ascending order.
    #[must_use]
    pub fn reachable_indices(&self, idx: usize) -> Vec<usize> {
        let n = self.graph.len();
        let mask = &self.comp_masks[self.comp_of[idx]];
        let mut out = Vec::new();
        for word_idx in 0..n {
            if mask[word_idx / 64] & (1 << (word_idx % 64)) != 0 && word_idx != idx {
                out.push(word_idx);
            }
        }
        out
    }

    /// Names of all packages transitively reachable from `idx`.
    #[must_use]
    pub fn reachable_names(&self, idx: usize) -> Vec<String> {
        self.reachable_indices(idx)
            .into_iter()
            .map(|i| self.graph.name_of(i).to_string())
            .collect()
    }

    /// Number of packages transitively reachable from `idx` (excluding
    /// itself), in O(V/64) via popcount — no allocation.
    #[must_use]
    pub fn closure_size(&self, idx: usize) -> usize {
        let mask = &self.comp_masks[self.comp_of[idx]];
        mask.iter()
            .map(|w| w.count_ones() as usize)
            .sum::<usize>()
            .saturating_sub(1)
    }
}

fn platform_matches(tag: &PlatformTag, target_os: TargetOS, target_arch: TargetArch) -> bool {
    let os_ok = tag.os == TargetOS::Any || tag.os == target_os;
    let arch_ok = tag.arch == TargetArch::Any || tag.arch == target_arch;
    os_ok && arch_ok
}

fn package_matches_platform(pkg: &Package, target_os: TargetOS, target_arch: TargetArch) -> bool {
    pkg.platform_tags.is_empty()
        || pkg
            .platform_tags
            .iter()
            .any(|tag| platform_matches(tag, target_os, target_arch))
}

/// Rebuild a subgraph lockfile from the extracted packages: sorts them by
/// name, compacts the source list down to the sources actually referenced and
/// remaps `source_idx` accordingly, then attaches the given provenance.
fn assemble_subgraph(
    lockfile: &Lockfile,
    extracted_packages: &mut [Package],
    provenance: Vec<crate::provenance::ResolutionProvenance>,
) -> Lockfile {
    extracted_packages.sort_by(|a, b| a.name.cmp(&b.name));

    let used_source_indices: HashSet<usize> =
        extracted_packages.iter().map(|p| p.source_idx).collect();
    let mut source_mapping: HashMap<usize, usize> = HashMap::new();
    let mut new_sources = Vec::new();

    for (orig_idx, source) in lockfile.sources.iter().enumerate() {
        if used_source_indices.contains(&orig_idx) {
            source_mapping.insert(orig_idx, new_sources.len());
            new_sources.push(source.clone());
        }
    }

    for pkg in &mut extracted_packages.iter_mut() {
        if let Some(&new_idx) = source_mapping.get(&pkg.source_idx) {
            pkg.source_idx = new_idx;
        }
    }

    Lockfile {
        sources: new_sources,
        overrides: lockfile.overrides.clone(),
        features: lockfile.features.clone(),
        metadata: lockfile.metadata.clone(),
        workspace_root: lockfile.workspace_root.clone(),
        workspace_pkgs: lockfile.workspace_pkgs.clone(),
        hoist_boundaries: lockfile.hoist_boundaries.clone(),
        packages: extracted_packages.to_vec(),
        artifacts: lockfile.artifacts.clone(),
        patches: lockfile.patches.clone(),
        provenance,
        advisories: lockfile.advisories.clone(),
        licenses: lockfile.licenses.clone(),
        policies: lockfile.policies.clone(),
        trust_roots: lockfile.trust_roots.clone(),
        mirrors: lockfile.mirrors.clone(),
        root_rotations: lockfile.root_rotations.clone(),
        vex_entries: lockfile.vex_entries.clone(),
        compat: None,
    }
}

/// Two-way diff of name-sorted package lists (merge-join, O(n)).
#[must_use]
pub fn diff_lockfiles(old: &Lockfile, new: &Lockfile) -> LockfileDiff {
    let mut changes = Vec::new();
    let mut unchanged_count = 0;
    let mut i = 0;
    let mut j = 0;

    while i < old.packages.len() && j < new.packages.len() {
        let old_pkg = &old.packages[i];
        let new_pkg = &new.packages[j];

        match old_pkg.name.cmp(&new_pkg.name) {
            std::cmp::Ordering::Less => {
                changes.push(PackageChange::Removed(Box::new(old_pkg.clone())));
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                changes.push(PackageChange::Added(Box::new(new_pkg.clone())));
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if old_pkg.major == new_pkg.major
                    && old_pkg.minor == new_pkg.minor
                    && old_pkg.patch == new_pkg.patch
                    && old_pkg.hashes == new_pkg.hashes
                {
                    unchanged_count += 1;
                } else {
                    changes.push(PackageChange::Altered(
                        Box::new(old_pkg.clone()),
                        Box::new(new_pkg.clone()),
                    ));
                }
                i += 1;
                j += 1;
            }
        }
    }

    while i < old.packages.len() {
        changes.push(PackageChange::Removed(Box::new(old.packages[i].clone())));
        i += 1;
    }

    while j < new.packages.len() {
        changes.push(PackageChange::Added(Box::new(new.packages[j].clone())));
        j += 1;
    }

    LockfileDiff {
        changes,
        unchanged_count,
    }
}

/// True when `pkg` carries no platform tags or one matching the target.
#[must_use]
pub fn package_supports_platform(
    pkg: &Package,
    target_os: TargetOS,
    target_arch: TargetArch,
) -> bool {
    package_matches_platform(pkg, target_os, target_arch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{DepType, Dependency};

    /// Convenience: build a [`Graph`] view over a lockfile in tests.
    fn graph(lf: &Lockfile) -> Graph<'_> {
        Graph::new(lf).expect("test lockfiles never collide")
    }

    fn mock_pkg(
        name: &str,
        maj: u64,
        min: u64,
        pat: u64,
        deps: &[(&str, DepType)],
        tags: Vec<PlatformTag>,
    ) -> Package {
        Package {
            name: name.to_string(),
            logical_name: None,
            source_idx: 0,
            major: maj,
            minor: min,
            patch: pat,
            hashes: vec![],
            features: vec![],
            resolved_peers: vec![],
            dependencies: deps
                .iter()
                .map(|(n, ty)| Dependency {
                    name: n.to_string(),
                    dep_type: *ty,
                    requested_features: vec![],
                })
                .collect(),
            peer_requirements: vec![],
            platform_tags: tags,
            exports: vec![],
            artifacts: vec![],
            hook_hashes: vec![],
            patch_hash: None,
        }
    }

    #[test]
    fn test_platform_filter_excludes_non_matching() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            root_rotations: vec![],
            vex_entries: vec![],
            compat: None,
            packages: vec![
                mock_pkg("app", 1, 0, 0, &[("native-lib", DepType::Runtime)], vec![]),
                mock_pkg(
                    "native-lib",
                    1,
                    0,
                    0,
                    &[],
                    vec![PlatformTag {
                        os: TargetOS::Linux,
                        arch: TargetArch::X86_64,
                    }],
                ),
                mock_pkg(
                    "other-lib",
                    1,
                    0,
                    0,
                    &[],
                    vec![PlatformTag {
                        os: TargetOS::MacOS,
                        arch: TargetArch::Aarch64,
                    }],
                ),
            ],
        };
        let app_cid = crate::cid::content_id("app", 1, 0, 0);
        let res = graph(&lockfile)
            .extract_subgraph_platform(&[app_cid], TargetOS::Linux, TargetArch::X86_64)
            .unwrap();
        assert_eq!(res.packages.len(), 2);
        let names: Vec<&str> = res.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"app"));
        assert!(names.contains(&"native-lib"));
        assert!(!names.contains(&"other-lib"));
    }

    #[test]
    fn test_platform_filter_agnostic_included() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            root_rotations: vec![],
            vex_entries: vec![],
            compat: None,
            packages: vec![
                mock_pkg("app", 1, 0, 0, &[("pure-lib", DepType::Runtime)], vec![]),
                mock_pkg("pure-lib", 1, 0, 0, &[], vec![]),
            ],
        };
        let app_cid = crate::cid::content_id("app", 1, 0, 0);
        let res = graph(&lockfile)
            .extract_subgraph_platform(&[app_cid], TargetOS::Windows, TargetArch::X86_64)
            .unwrap();
        assert_eq!(res.packages.len(), 2);
    }

    #[test]
    fn test_platform_filter_any_arch() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            root_rotations: vec![],
            vex_entries: vec![],
            compat: None,
            packages: vec![
                mock_pkg("app", 1, 0, 0, &[("napi", DepType::Runtime)], vec![]),
                mock_pkg(
                    "napi",
                    1,
                    0,
                    0,
                    &[],
                    vec![PlatformTag {
                        os: TargetOS::Linux,
                        arch: TargetArch::Any,
                    }],
                ),
            ],
        };
        let app_cid = crate::cid::content_id("app", 1, 0, 0);
        let res = graph(&lockfile)
            .extract_subgraph_platform(&[app_cid], TargetOS::Linux, TargetArch::Aarch64)
            .unwrap();
        assert_eq!(res.packages.len(), 2);
    }

    #[test]
    fn test_platform_filter_multiple_tags() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            root_rotations: vec![],
            vex_entries: vec![],
            compat: None,
            packages: vec![
                mock_pkg("app", 1, 0, 0, &[("multi", DepType::Runtime)], vec![]),
                mock_pkg(
                    "multi",
                    1,
                    0,
                    0,
                    &[],
                    vec![
                        PlatformTag {
                            os: TargetOS::Linux,
                            arch: TargetArch::X86_64,
                        },
                        PlatformTag {
                            os: TargetOS::MacOS,
                            arch: TargetArch::Aarch64,
                        },
                    ],
                ),
            ],
        };
        let app_cid = crate::cid::content_id("app", 1, 0, 0);
        let res_linux = graph(&lockfile)
            .extract_subgraph_platform(&[app_cid], TargetOS::Linux, TargetArch::X86_64)
            .unwrap();
        assert_eq!(res_linux.packages.len(), 2);
        let res_mac = graph(&lockfile)
            .extract_subgraph_platform(&[app_cid], TargetOS::MacOS, TargetArch::Aarch64)
            .unwrap();
        assert_eq!(res_mac.packages.len(), 2);
        let res_win = graph(&lockfile)
            .extract_subgraph_platform(&[app_cid], TargetOS::Windows, TargetArch::X86_64)
            .unwrap();
        assert_eq!(res_win.packages.len(), 1);
    }

    #[test]
    fn test_platform_filter_excludes_transitive_non_matching() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            root_rotations: vec![],
            vex_entries: vec![],
            compat: None,
            packages: vec![
                mock_pkg("app", 1, 0, 0, &[("mid", DepType::Runtime)], vec![]),
                mock_pkg("mid", 1, 0, 0, &[("leaf", DepType::Runtime)], vec![]),
                mock_pkg(
                    "leaf",
                    1,
                    0,
                    0,
                    &[],
                    vec![PlatformTag {
                        os: TargetOS::MacOS,
                        arch: TargetArch::Aarch64,
                    }],
                ),
            ],
        };
        let app_cid = crate::cid::content_id("app", 1, 0, 0);
        let res = graph(&lockfile)
            .extract_subgraph_platform(&[app_cid], TargetOS::Linux, TargetArch::X86_64)
            .unwrap();
        assert_eq!(res.packages.len(), 2);
        let names: Vec<&str> = res.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"app"));
        assert!(names.contains(&"mid"));
        assert!(!names.contains(&"leaf"));
    }

    #[test]
    fn test_platform_filter_no_packages_error() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            root_rotations: vec![],
            vex_entries: vec![],
            compat: None,
            packages: vec![mock_pkg(
                "app",
                1,
                0,
                0,
                &[],
                vec![PlatformTag {
                    os: TargetOS::MacOS,
                    arch: TargetArch::Aarch64,
                }],
            )],
        };
        let app_cid = crate::cid::content_id("app", 1, 0, 0);
        let res = graph(&lockfile).extract_subgraph_platform(
            &[app_cid],
            TargetOS::Linux,
            TargetArch::X86_64,
        );
        assert!(matches!(res, Err(Error::NoPackagesForPlatform { .. })));
    }

    fn make_graph_lockfile(packages: Vec<Package>) -> Lockfile {
        Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            root_rotations: vec![],
            vex_entries: vec![],
            compat: None,
            packages,
        }
    }

    #[test]
    fn test_topological_sort_simple() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("c", 1, 0, 0, &[("b", DepType::Runtime)], vec![]),
            mock_pkg("a", 1, 0, 0, &[("b", DepType::Runtime)], vec![]),
            mock_pkg("b", 1, 0, 0, &[], vec![]),
        ]);
        let order = graph(&lockfile).topological_sort().unwrap();
        let names: Vec<&str> = order
            .iter()
            .map(|&i| lockfile.packages[i].name.as_str())
            .collect();
        let b_pos = names.iter().position(|&n| n == "b").unwrap();
        let a_pos = names.iter().position(|&n| n == "a").unwrap();
        let c_pos = names.iter().position(|&n| n == "c").unwrap();
        assert!(b_pos < a_pos);
        assert!(b_pos < c_pos);
    }

    #[test]
    fn test_topological_sort_lexicographic_tiebreak() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("z", 1, 0, 0, &[], vec![]),
            mock_pkg("a", 1, 0, 0, &[], vec![]),
            mock_pkg("m", 1, 0, 0, &[], vec![]),
        ]);
        let order = graph(&lockfile).topological_sort().unwrap();
        let names: Vec<&str> = order
            .iter()
            .map(|&i| lockfile.packages[i].name.as_str())
            .collect();
        assert_eq!(names, vec!["a", "m", "z"]);
    }

    #[test]
    fn test_topological_sort_detects_cycle() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("a", 1, 0, 0, &[("b", DepType::Runtime)], vec![]),
            mock_pkg("b", 1, 0, 0, &[("a", DepType::Runtime)], vec![]),
        ]);
        let res = graph(&lockfile).topological_sort();
        assert!(res.is_err());
        let cycle = res.unwrap_err();
        assert!(cycle.contains(&"a".to_string()));
        assert!(cycle.contains(&"b".to_string()));
    }

    #[test]
    fn test_topological_sort_self_dependency() {
        let lockfile = make_graph_lockfile(vec![mock_pkg(
            "a",
            1,
            0,
            0,
            &[("a", DepType::Runtime)],
            vec![],
        )]);
        let res = graph(&lockfile).topological_sort();
        assert!(res.is_err());
    }

    #[test]
    fn test_dependents_of_direct() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("lib", DepType::Runtime)], vec![]),
            mock_pkg("lib", 1, 0, 0, &[], vec![]),
        ]);
        let deps = graph(&lockfile).dependents_of("lib");
        assert_eq!(deps, vec!["app"]);
    }

    #[test]
    fn test_dependents_of_transitive() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("mid", DepType::Runtime)], vec![]),
            mock_pkg("mid", 1, 0, 0, &[("leaf", DepType::Runtime)], vec![]),
            mock_pkg("leaf", 1, 0, 0, &[], vec![]),
        ]);
        let deps = graph(&lockfile).dependents_of("leaf");
        assert_eq!(deps, vec!["app", "mid"]);
    }

    #[test]
    fn test_dependents_of_no_dependents() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("lib", DepType::Runtime)], vec![]),
            mock_pkg("lib", 1, 0, 0, &[], vec![]),
        ]);
        let deps = graph(&lockfile).dependents_of("app");
        assert_eq!(deps, [] as [String; 0]);
    }

    #[test]
    fn test_dependents_of_unknown_package() {
        let lockfile = make_graph_lockfile(vec![mock_pkg("app", 1, 0, 0, &[], vec![])]);
        let deps = graph(&lockfile).dependents_of("nonexistent");
        assert_eq!(deps, [] as [String; 0]);
    }

    #[test]
    fn test_transitive_deps_direct() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("lib", DepType::Runtime)], vec![]),
            mock_pkg("lib", 1, 0, 0, &[], vec![]),
        ]);
        let deps = graph(&lockfile).transitive_deps("app");
        assert_eq!(deps, HashSet::from(["lib".to_string()]));
    }

    #[test]
    fn test_transitive_deps_deep() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("mid", DepType::Runtime)], vec![]),
            mock_pkg("mid", 1, 0, 0, &[("leaf", DepType::Runtime)], vec![]),
            mock_pkg("leaf", 1, 0, 0, &[], vec![]),
        ]);
        let deps = graph(&lockfile).transitive_deps("app");
        assert_eq!(deps, HashSet::from(["mid".to_string(), "leaf".to_string()]));
    }

    #[test]
    fn test_transitive_deps_excludes_self() {
        let lockfile = make_graph_lockfile(vec![mock_pkg("app", 1, 0, 0, &[], vec![])]);
        let deps = graph(&lockfile).transitive_deps("app");
        assert!(deps.is_empty());
    }

    #[test]
    fn test_transitive_deps_unknown_package() {
        let lockfile = make_graph_lockfile(vec![mock_pkg("app", 1, 0, 0, &[], vec![])]);
        let deps = graph(&lockfile).transitive_deps("nonexistent");
        assert!(deps.is_empty());
    }

    #[test]
    fn test_leaf_packages_basic() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("lib", DepType::Runtime)], vec![]),
            mock_pkg("lib", 1, 0, 0, &[], vec![]),
        ]);
        let leaves = graph(&lockfile).leaf_packages();
        let names: Vec<&str> = leaves.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["app"]);
    }

    #[test]
    fn test_leaf_packages_multiple() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg(
                "app",
                1,
                0,
                0,
                &[("a", DepType::Runtime), ("b", DepType::Runtime)],
                vec![],
            ),
            mock_pkg("a", 1, 0, 0, &[], vec![]),
            mock_pkg("b", 1, 0, 0, &[], vec![]),
        ]);
        let leaves = graph(&lockfile).leaf_packages();
        let names: Vec<&str> = leaves.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["app"]);
    }

    #[test]
    fn test_leaf_packages_sorted() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("z", 1, 0, 0, &[], vec![]),
            mock_pkg("a", 1, 0, 0, &[], vec![]),
        ]);
        let leaves = graph(&lockfile).leaf_packages();
        let names: Vec<&str> = leaves.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["a", "z"]);
    }

    #[test]
    fn test_detect_cycle_no_cycle() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("a", 1, 0, 0, &[("b", DepType::Runtime)], vec![]),
            mock_pkg("b", 1, 0, 0, &[], vec![]),
        ]);
        assert!(graph(&lockfile).detect_cycle().is_none());
    }

    #[test]
    fn test_detect_cycle_simple() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("a", 1, 0, 0, &[("b", DepType::Runtime)], vec![]),
            mock_pkg("b", 1, 0, 0, &[("a", DepType::Runtime)], vec![]),
        ]);
        let cycle = graph(&lockfile).detect_cycle().unwrap();
        assert!(cycle.contains(&"a".to_string()));
        assert!(cycle.contains(&"b".to_string()));
    }

    #[test]
    fn test_detect_cycle_self() {
        let lockfile = make_graph_lockfile(vec![mock_pkg(
            "a",
            1,
            0,
            0,
            &[("a", DepType::Runtime)],
            vec![],
        )]);
        let cycle = graph(&lockfile).detect_cycle().unwrap();
        assert_eq!(cycle, vec!["a"]);
    }

    #[test]
    fn test_detect_cycle_three_node() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("a", 1, 0, 0, &[("b", DepType::Runtime)], vec![]),
            mock_pkg("b", 1, 0, 0, &[("c", DepType::Runtime)], vec![]),
            mock_pkg("c", 1, 0, 0, &[("a", DepType::Runtime)], vec![]),
        ]);
        let cycle = graph(&lockfile).detect_cycle().unwrap();
        assert_eq!(cycle.len(), 3);
        assert!(cycle.contains(&"a".to_string()));
        assert!(cycle.contains(&"b".to_string()));
        assert!(cycle.contains(&"c".to_string()));
    }

    #[test]
    fn test_detect_cycle_isolated_component() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("a", 1, 0, 0, &[], vec![]),
            mock_pkg("x", 1, 0, 0, &[("y", DepType::Runtime)], vec![]),
            mock_pkg("y", 1, 0, 0, &[("x", DepType::Runtime)], vec![]),
        ]);
        let cycle = graph(&lockfile).detect_cycle().unwrap();
        assert!(cycle.contains(&"x".to_string()));
        assert!(cycle.contains(&"y".to_string()));
    }

    #[test]
    fn test_would_create_cycle_no() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("lib", DepType::Runtime)], vec![]),
            mock_pkg("lib", 1, 0, 0, &[], vec![]),
            mock_pkg("new-dep", 1, 0, 0, &[], vec![]),
        ]);
        assert!(!graph(&lockfile).would_create_cycle("app", &["new-dep".to_string()]));
    }

    #[test]
    fn test_would_create_cycle_yes() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("lib", DepType::Runtime)], vec![]),
            mock_pkg("lib", 1, 0, 0, &[("app", DepType::Runtime)], vec![]),
        ]);
        assert!(graph(&lockfile).would_create_cycle("lib", &["app".to_string()]));
    }

    #[test]
    fn test_would_create_cycle_self() {
        let lockfile = make_graph_lockfile(vec![mock_pkg("app", 1, 0, 0, &[], vec![])]);
        assert!(graph(&lockfile).would_create_cycle("app", &["app".to_string()]));
    }

    #[test]
    fn test_would_create_cycle_transitive() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("mid", DepType::Runtime)], vec![]),
            mock_pkg("mid", 1, 0, 0, &[("leaf", DepType::Runtime)], vec![]),
            mock_pkg("leaf", 1, 0, 0, &[], vec![]),
        ]);
        assert!(graph(&lockfile).would_create_cycle("leaf", &["app".to_string()]));
    }

    #[test]
    fn test_would_create_cycle_unknown_dep() {
        let lockfile = make_graph_lockfile(vec![mock_pkg("app", 1, 0, 0, &[], vec![])]);
        assert!(!graph(&lockfile).would_create_cycle("app", &["nonexistent".to_string()]));
    }

    #[test]
    fn test_extract_subgraph_preserves_provenance() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![
                crate::provenance::ResolutionProvenance {
                    package_name: "app".to_string(),
                    constraint: String::new(),
                    constrained_by: String::new(),
                    dep_type: DepType::Runtime,
                    source_type: crate::provenance::ProvenanceSourceType::Registry,
                    depth: 0,
                },
                crate::provenance::ResolutionProvenance {
                    package_name: "lib".to_string(),
                    constraint: "^1.0.0".to_string(),
                    constrained_by: "app".to_string(),
                    dep_type: DepType::Runtime,
                    source_type: crate::provenance::ProvenanceSourceType::Registry,
                    depth: 1,
                },
                crate::provenance::ResolutionProvenance {
                    package_name: "unused".to_string(),
                    constraint: "^1.0.0".to_string(),
                    constrained_by: "other".to_string(),
                    dep_type: DepType::Runtime,
                    source_type: crate::provenance::ProvenanceSourceType::Registry,
                    depth: 1,
                },
            ],
            packages: vec![
                mock_pkg("app", 1, 0, 0, &[("lib", DepType::Runtime)], vec![]),
                mock_pkg("lib", 1, 0, 0, &[], vec![]),
                mock_pkg("unused", 1, 0, 0, &[], vec![]),
            ],
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            root_rotations: vec![],
            vex_entries: vec![],
            compat: None,
        };
        let app_cid = crate::cid::content_id("app", 1, 0, 0);
        let sub = graph(&lockfile).extract_subgraph(&[app_cid]).unwrap();
        let prov_names: Vec<&str> = sub
            .provenance
            .iter()
            .map(|p| p.package_name.as_str())
            .collect();
        assert!(prov_names.contains(&"app"));
        assert!(prov_names.contains(&"lib"));
        assert!(!prov_names.contains(&"unused"));
    }

    #[test]
    fn test_would_create_cycle_unknown_package() {
        let lockfile = make_graph_lockfile(vec![mock_pkg("app", 1, 0, 0, &[], vec![])]);
        assert!(!graph(&lockfile).would_create_cycle("nonexistent", &["app".to_string()]));
    }

    #[test]
    fn test_runtime_deps_only_follows_runtime() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg(
                "app",
                1,
                0,
                0,
                &[("rt-lib", DepType::Runtime), ("dev-lib", DepType::Dev)],
                vec![],
            ),
            mock_pkg("rt-lib", 1, 0, 0, &[("deep-rt", DepType::Runtime)], vec![]),
            mock_pkg("dev-lib", 1, 0, 0, &[], vec![]),
            mock_pkg("deep-rt", 1, 0, 0, &[], vec![]),
        ]);
        let deps = graph(&lockfile).runtime_deps("app");
        assert!(deps.contains("rt-lib"));
        assert!(deps.contains("deep-rt"));
        assert!(!deps.contains("dev-lib"));
    }

    #[test]
    fn test_dev_deps_only_follows_dev() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg(
                "app",
                1,
                0,
                0,
                &[("rt-lib", DepType::Runtime), ("dev-lib", DepType::Dev)],
                vec![],
            ),
            mock_pkg("rt-lib", 1, 0, 0, &[], vec![]),
            mock_pkg("dev-lib", 1, 0, 0, &[("deep-dev", DepType::Dev)], vec![]),
            mock_pkg("deep-dev", 1, 0, 0, &[], vec![]),
        ]);
        let deps = graph(&lockfile).dev_deps("app");
        assert!(deps.contains("dev-lib"));
        assert!(deps.contains("deep-dev"));
        assert!(!deps.contains("rt-lib"));
    }

    #[test]
    fn test_runtime_deps_ignores_peer() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("peer-lib", DepType::Peer)], vec![]),
            mock_pkg("peer-lib", 1, 0, 0, &[], vec![]),
        ]);
        let deps = graph(&lockfile).runtime_deps("app");
        assert!(!deps.contains("peer-lib"));
    }

    #[test]
    fn test_runtime_deps_unknown_package() {
        let lockfile = make_graph_lockfile(vec![mock_pkg("app", 1, 0, 0, &[], vec![])]);
        let deps = graph(&lockfile).runtime_deps("nonexistent");
        assert!(deps.is_empty());
    }

    #[test]
    fn test_runtime_dependents_of() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("lib", DepType::Runtime)], vec![]),
            mock_pkg("test-util", 1, 0, 0, &[("lib", DepType::Dev)], vec![]),
            mock_pkg("lib", 1, 0, 0, &[], vec![]),
        ]);
        let dependents = graph(&lockfile).runtime_dependents_of("lib");
        assert!(dependents.contains(&"app".to_string()));
        assert!(!dependents.contains(&"test-util".to_string()));
    }

    #[test]
    fn test_dev_dependents_of() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("lib", DepType::Runtime)], vec![]),
            mock_pkg("test-util", 1, 0, 0, &[("lib", DepType::Dev)], vec![]),
            mock_pkg("lib", 1, 0, 0, &[], vec![]),
        ]);
        let dependents = graph(&lockfile).dev_dependents_of("lib");
        assert!(dependents.contains(&"test-util".to_string()));
        assert!(!dependents.contains(&"app".to_string()));
    }

    #[test]
    fn test_runtime_dependents_of_transitive() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("top", 1, 0, 0, &[("mid", DepType::Runtime)], vec![]),
            mock_pkg("mid", 1, 0, 0, &[("leaf", DepType::Runtime)], vec![]),
            mock_pkg("leaf", 1, 0, 0, &[], vec![]),
        ]);
        let dependents = graph(&lockfile).runtime_dependents_of("leaf");
        assert!(dependents.contains(&"mid".to_string()));
        assert!(dependents.contains(&"top".to_string()));
    }

    #[test]
    fn test_has_dep_path_runtime_true() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("mid", DepType::Runtime)], vec![]),
            mock_pkg("mid", 1, 0, 0, &[("leaf", DepType::Runtime)], vec![]),
            mock_pkg("leaf", 1, 0, 0, &[], vec![]),
        ]);
        assert!(graph(&lockfile).has_dep_path("app", "leaf", EdgeFilter::Runtime));
    }

    #[test]
    fn test_has_dep_path_runtime_false_via_dev() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("mid", DepType::Dev)], vec![]),
            mock_pkg("mid", 1, 0, 0, &[("leaf", DepType::Runtime)], vec![]),
            mock_pkg("leaf", 1, 0, 0, &[], vec![]),
        ]);
        assert!(!graph(&lockfile).has_dep_path("app", "leaf", EdgeFilter::Runtime));
    }

    #[test]
    fn test_has_dep_path_same_package() {
        let lockfile = make_graph_lockfile(vec![mock_pkg("app", 1, 0, 0, &[], vec![])]);
        assert!(graph(&lockfile).has_dep_path("app", "app", EdgeFilter::Runtime));
    }

    #[test]
    fn test_has_dep_path_unknown_source() {
        let lockfile = make_graph_lockfile(vec![mock_pkg("app", 1, 0, 0, &[], vec![])]);
        assert!(!graph(&lockfile).has_dep_path("nonexistent", "app", EdgeFilter::Runtime));
    }

    #[test]
    fn test_has_dep_path_unknown_target() {
        let lockfile = make_graph_lockfile(vec![mock_pkg("app", 1, 0, 0, &[], vec![])]);
        assert!(!graph(&lockfile).has_dep_path("app", "nonexistent", EdgeFilter::Runtime));
    }

    #[test]
    fn test_dep_count_runtime() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg(
                "app",
                1,
                0,
                0,
                &[
                    ("lib1", DepType::Runtime),
                    ("lib2", DepType::Runtime),
                    ("dev1", DepType::Dev),
                ],
                vec![],
            ),
            mock_pkg("lib1", 1, 0, 0, &[], vec![]),
            mock_pkg("lib2", 1, 0, 0, &[], vec![]),
            mock_pkg("dev1", 1, 0, 0, &[], vec![]),
        ]);
        assert_eq!(graph(&lockfile).dep_count("app", DepType::Runtime), 2);
    }

    #[test]
    fn test_dep_count_dev() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg(
                "app",
                1,
                0,
                0,
                &[
                    ("lib1", DepType::Runtime),
                    ("dev1", DepType::Dev),
                    ("dev2", DepType::Dev),
                ],
                vec![],
            ),
            mock_pkg("lib1", 1, 0, 0, &[], vec![]),
            mock_pkg("dev1", 1, 0, 0, &[], vec![]),
            mock_pkg("dev2", 1, 0, 0, &[], vec![]),
        ]);
        assert_eq!(graph(&lockfile).dep_count("app", DepType::Dev), 2);
    }

    #[test]
    fn test_dep_count_peer() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, &[("peer1", DepType::Peer)], vec![]),
            mock_pkg("peer1", 1, 0, 0, &[], vec![]),
        ]);
        assert_eq!(graph(&lockfile).dep_count("app", DepType::Peer), 1);
    }

    #[test]
    fn test_dep_count_unknown_package() {
        let lockfile = make_graph_lockfile(vec![mock_pkg("app", 1, 0, 0, &[], vec![])]);
        assert_eq!(
            graph(&lockfile).dep_count("nonexistent", DepType::Runtime),
            0
        );
    }
}
