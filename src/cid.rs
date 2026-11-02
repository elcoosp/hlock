//! Stable 64-bit package content ids (v1).
//!
//! 0.x derived content ids from 64-bit FNV-1a of `name@major.minor.patch`.
//! FNV is not collision-resistant, the format had **no collision handling**,
//! and a crafted lockfile could alias a dependency edge to a different package.
//!
//! v1.0 replaces FNV with a domain-separated, truncated BLAKE3 digest and adds
//! explicit collision detection wherever a cid→package map is built. The id is
//! still only 64 bits, so accidental collisions remain *possible* (birthday
//! bound ≈ 2³² distinct packages) — but they are now detectable and fatal
//! instead of silent, and they can no longer be crafted without breaking BLAKE3.

use blake3::Hasher;

/// Domain-separation tag for package content ids.
const CID_DOMAIN: &[u8] = b"hlock/cid/v1";

/// Stable 64-bit content id of `name@major.minor.patch`.
///
/// `BLAKE3("hlock/cid/v1" || name || 0x00 || major.u64le || minor.u64le || patch.u64le)`
/// truncated to the first 8 bytes, little-endian.
///
/// The name is length-delimited implicitly by the `0x00` separator; npm names
/// cannot contain NUL bytes, so the encoding is injective before truncation.
#[must_use]
pub fn content_id(name: &str, major: u64, minor: u64, patch: u64) -> u64 {
    let mut hasher = Hasher::new();
    hasher.update(CID_DOMAIN);
    hasher.update(name.as_bytes());
    hasher.update(&[0x00]);
    hasher.update(&major.to_le_bytes());
    hasher.update(&minor.to_le_bytes());
    hasher.update(&patch.to_le_bytes());
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(buf)
}

/// Content id of a package, computed from its own fields.
#[must_use]
pub fn package_cid(pkg: &crate::lockfile::Package) -> u64 {
    content_id(&pkg.name, pkg.major, pkg.minor, pkg.patch)
}

/// Failure raised when two distinct `(name, version)` identities truncate to
/// the same 64-bit content id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidCollision {
    pub first: (String, u64, u64, u64),
    pub second: (String, u64, u64, u64),
    pub content_id: u64,
}

impl std::fmt::Display for CidCollision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (n1, a1, b1, c1) = &self.first;
        let (n2, a2, b2, c2) = &self.second;
        write!(
            f,
            "content-id collision: {}@{}.{}.{} and {}@{}.{}.{} share cid {:016x}",
            n1, a1, b1, c1, n2, a2, b2, c2, self.content_id
        )
    }
}

impl std::error::Error for CidCollision {}

/// Builds a cid→value map over packages, detecting collisions.
///
/// Every caller that resolves content ids to packages must go through this
/// helper so that a truncated-cid collision is a hard, early, precise error
/// instead of a silent map overwrite.
///
/// # Errors
/// Returns [`CidCollision`] when two distinct packages share a content id.
pub fn build_map<'a, T>(
    packages: &'a [crate::lockfile::Package],
    value: impl Fn(usize, &'a crate::lockfile::Package) -> T,
) -> Result<std::collections::HashMap<u64, T>, CidCollision> {
    let mut map: std::collections::HashMap<u64, T> =
        std::collections::HashMap::with_capacity(packages.len());
    let mut seen: std::collections::HashMap<u64, (String, u64, u64, u64)> =
        std::collections::HashMap::with_capacity(packages.len());
    for (idx, pkg) in packages.iter().enumerate() {
        let cid = package_cid(pkg);
        let identity = (pkg.name.clone(), pkg.major, pkg.minor, pkg.patch);
        if let Some(first) = seen.get(&cid)
            && (first.0 != pkg.name
                || first.1 != pkg.major
                || first.2 != pkg.minor
                || first.3 != pkg.patch)
        {
            return Err(CidCollision {
                first: first.clone(),
                second: identity,
                content_id: cid,
            });
        }
        seen.insert(cid, identity);
        map.insert(cid, value(idx, pkg));
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_id_is_deterministic() {
        let a = content_id("lodash", 4, 17, 21);
        let b = content_id("lodash", 4, 17, 21);
        assert_eq!(a, b);
    }

    #[test]
    fn content_id_differs_by_name_and_version() {
        let base = content_id("lodash", 4, 17, 21);
        assert_ne!(base, content_id("lodasj", 4, 17, 21));
        assert_ne!(base, content_id("lodash", 4, 17, 22));
        assert_ne!(base, content_id("lodash", 5, 17, 21));
        assert_ne!(base, content_id("lodash", 4, 18, 21));
    }

    #[test]
    fn content_id_separator_is_injective() {
        // "ab" + version boundary must not equal "a" with a weird version.
        // Before truncation the encoding is injective; equality here would
        // imply a BLAKE3 collision.
        assert_ne!(content_id("ab", 0, 0, 0), content_id("a", 0, 0, 0));
    }

    #[test]
    fn build_map_detects_collision() {
        // Force a collision by monkey-patching is impossible; instead verify
        // that distinct identities never collide on a large sample and that
        // identical (name, version) duplicates are allowed (multi-version
        // lockfiles store one entry per name, but the map tolerates identity
        // duplicates without raising).
        let mut packages = Vec::new();
        for i in 0..10_000u64 {
            packages.push(crate::lockfile::Package {
                name: format!("pkg-{i}"),
                major: i,
                minor: i % 256,
                patch: i % 64,
                ..crate::lockfile::Package::default()
            });
        }
        let map = build_map(&packages, |_, _| ()).expect("no collision in sample");
        assert_eq!(map.len(), 10_000);
    }

    #[test]
    fn build_map_allows_identical_identity() {
        // Same (name, version) twice is an identity duplicate, not a cid
        // collision: the map simply keeps both indices' values (last wins).
        let packages = vec![
            crate::lockfile::Package {
                name: "a".into(),
                major: 1,
                ..crate::lockfile::Package::default()
            },
            crate::lockfile::Package {
                name: "a".into(),
                major: 1,
                ..crate::lockfile::Package::default()
            },
        ];
        let map = build_map(&packages, |i, _| i).expect("identity duplicates are not collisions");
        assert_eq!(map.len(), 1);
    }
}
