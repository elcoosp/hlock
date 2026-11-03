use crate::error::Error;
use crate::lockfile::{Attestation, PeerResolution, SlsaPredicate};

/// Wire-format payload version for the 1.0 series.
///
/// 0.x wrote `0x08`; the 1.0 format changes content-id derivation to
/// domain-separated BLAKE3-64 and tightens decode strictness, so the version
/// byte moves to `0x10`. Old lockfiles are rejected with a migration hint.
pub const PAYLOAD_VERSION: u8 = 0x10;

#[derive(Debug, Clone)]
pub struct HashPayload {
    pub algo_id: u8,
    pub digest: Vec<u8>,
    pub attestation: Attestation,
}

pub struct DepPayload {
    pub content_id: u64,
    pub dep_type: u8,
    pub target_os: Option<u8>,
    pub target_arch: Option<u8>,
    pub req_feat_indices: Vec<usize>,
}

pub struct PeerReqPayload {
    pub peer_name: String,
    pub version_range: String,
    pub is_optional: bool,
}

pub struct PlatformTagPayload {
    pub os_id: u8,
    pub arch_id: u8,
}

pub struct HookHashPayload {
    pub hook_type: String,
    pub hash_algo: u8,
    pub digest: Vec<u8>,
}

pub struct ExportPayload {
    pub identifier: String,
    pub hash_algo: u8,
    pub digest: Vec<u8>,
}

pub struct ArtifactPayload {
    pub os_id: u8,
    pub arch_id: u8,
    pub hash_algo: u8,
    pub digest: Vec<u8>,
}

pub struct PayloadData {
    pub logical_name: Option<String>,
    pub source_idx: usize,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub hashes: Vec<HashPayload>,
    pub features: Vec<String>,
    pub resolved_peers: Vec<PeerResolution>,
    pub deps: Vec<DepPayload>,
    pub peer_requirements: Vec<PeerReqPayload>,
    pub platform_tags: Vec<PlatformTagPayload>,
    pub exports: Vec<ExportPayload>,
    pub artifacts: Vec<ArtifactPayload>,
    pub hook_hashes: Vec<HookHashPayload>,
    pub patch_hash: Option<(u8, Vec<u8>)>,
}

///
/// # Errors
///
/// Returns `Err` if payload validation fails.
pub fn pack_payload(data: &PayloadData) -> Result<Vec<u8>, Error> {
    validate_payload(data)?;
    // Empirical sizing: an empty payload is 33 bytes (version + 32-byte
    // trailer); typical packages land in the 128-512 byte range.
    let mut buf = Vec::with_capacity(160);

    buf.push(PAYLOAD_VERSION);
    pack_logical_name(&mut buf, data.logical_name.as_ref());
    crate::varint::push_varint(&mut buf, data.source_idx as u64);
    crate::varint::push_varint(&mut buf, data.major);
    crate::varint::push_varint(&mut buf, data.minor);
    crate::varint::push_varint(&mut buf, data.patch);
    pack_hashes(&mut buf, &data.hashes);
    pack_features(&mut buf, &data.features);
    pack_resolved_peers(&mut buf, &data.resolved_peers);
    pack_deps(&mut buf, &data.deps);
    pack_peer_requirements(&mut buf, &data.peer_requirements);
    pack_platform_tags(&mut buf, &data.platform_tags);
    pack_exports(&mut buf, &data.exports);
    pack_artifacts(&mut buf, &data.artifacts);
    pack_hook_hashes(&mut buf, &data.hook_hashes);
    pack_patch_hash(&mut buf, data.patch_hash.as_ref());

    let hash = blake3::hash(&buf);
    buf.extend_from_slice(hash.as_bytes());
    Ok(buf)
}

/// Maximum pre-allocation for count-driven collections. Counts come from
/// attacker-controlled varints; the true element count is bounded by the
/// remaining input anyway (every element consumes at least one byte), so a
/// huge count is truncated by the input before the loop ever reaches it.
const MAX_PREALLOC: usize = 4096;

/// Rejects payload data that cannot round-trip the wire format **before** any
/// bytes are written: digests must fit the 1-byte wire length and the patch
/// hash must be exactly 32 bytes (fixed-width field).
///
/// # Errors
/// Returns [`Error::DigestTooLong`] for oversized digests and
/// [`Error::InvalidPatchHashLength`] for a patch hash that is not 32 bytes.
fn validate_payload(data: &PayloadData) -> Result<(), Error> {
    for hash in &data.hashes {
        check_digest_len(&hash.digest)?;
        if let Attestation::ExternalBundleSha256(bundle) = &hash.attestation {
            check_digest_len(bundle)?;
        }
    }
    for ex in &data.exports {
        check_digest_len(&ex.digest)?;
    }
    for art in &data.artifacts {
        check_digest_len(&art.digest)?;
    }
    for hook in &data.hook_hashes {
        check_digest_len(&hook.digest)?;
    }
    if let Some((_, digest)) = &data.patch_hash {
        check_digest_len(digest)?;
        if digest.len() != 32 {
            return Err(Error::InvalidPatchHashLength { len: digest.len() });
        }
    }
    Ok(())
}

/// Appends a length-prefixed UTF-8 string field (varint length + raw bytes).
fn push_str_field(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    crate::varint::push_varint(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

/// Appends a raw digest preceded by its one-byte length.
///
/// The wire format stores digest lengths in a single byte; [`validate_payload`]
/// has already rejected lengths of 256 or more, so the cast cannot truncate.
fn push_digest(buf: &mut Vec<u8>, digest: &[u8]) {
    debug_assert!(digest.len() < 256, "validated by validate_payload");
    #[allow(clippy::cast_possible_truncation)] // enforced by debug_assert + validate_payload
    buf.push(digest.len() as u8);
    buf.extend_from_slice(digest);
}

/// Returns `Err` when `digest` cannot round-trip through the 1-byte wire length.
fn check_digest_len(digest: &[u8]) -> Result<(), Error> {
    if digest.len() >= 256 {
        return Err(Error::DigestTooLong { len: digest.len() });
    }
    Ok(())
}

fn pack_logical_name(buf: &mut Vec<u8>, logical_name: Option<&String>) {
    match logical_name {
        Some(name) => push_str_field(buf, name),
        None => buf.push(0x00),
    }
}

fn pack_hashes(buf: &mut Vec<u8>, hashes: &[HashPayload]) {
    crate::varint::push_varint(buf, hashes.len() as u64);
    for hash in hashes {
        buf.push(hash.algo_id);
        push_digest(buf, &hash.digest);

        match &hash.attestation {
            Attestation::None => buf.push(0x00),
            Attestation::ExternalBundleSha256(bundle_hash) => {
                buf.push(0x01);
                buf.extend_from_slice(bundle_hash);
            }
            Attestation::InlineSlsa(pred) => {
                buf.push(0x02);
                push_str_field(buf, &pred.builder);
                push_str_field(buf, &pred.source);
            }
        }
    }
}

fn pack_features(buf: &mut Vec<u8>, features: &[String]) {
    crate::varint::push_varint(buf, features.len() as u64);
    for feat in features {
        push_str_field(buf, feat);
    }
}

fn pack_resolved_peers(buf: &mut Vec<u8>, peers: &[PeerResolution]) {
    crate::varint::push_varint(buf, peers.len() as u64);
    for peer in peers {
        push_str_field(buf, &peer.peer_name);
        buf.extend_from_slice(&peer.satisfied_by_content_id.to_le_bytes());
        buf.push(u8::from(peer.is_hoisted_to_root));
    }
}

fn pack_deps(buf: &mut Vec<u8>, deps: &[DepPayload]) {
    crate::varint::push_varint(buf, deps.len() as u64);
    for dep in deps {
        buf.extend_from_slice(&dep.content_id.to_le_bytes());
        buf.push(dep.dep_type);
        if dep.dep_type == 0x04 {
            buf.push(dep.target_os.unwrap_or(0x00));
            buf.push(dep.target_arch.unwrap_or(0x00));
        }
        crate::varint::push_varint(buf, dep.req_feat_indices.len() as u64);
        for idx in &dep.req_feat_indices {
            crate::varint::push_varint(buf, *idx as u64);
        }
    }
}

fn pack_peer_requirements(buf: &mut Vec<u8>, reqs: &[PeerReqPayload]) {
    crate::varint::push_varint(buf, reqs.len() as u64);
    for req in reqs {
        push_str_field(buf, &req.peer_name);
        push_str_field(buf, &req.version_range);
        buf.push(u8::from(req.is_optional));
    }
}

fn pack_platform_tags(buf: &mut Vec<u8>, tags: &[PlatformTagPayload]) {
    crate::varint::push_varint(buf, tags.len() as u64);
    for tag in tags {
        buf.push(tag.os_id);
        buf.push(tag.arch_id);
    }
}

fn pack_exports(buf: &mut Vec<u8>, exports: &[ExportPayload]) {
    crate::varint::push_varint(buf, exports.len() as u64);
    for ex in exports {
        push_str_field(buf, &ex.identifier);
        buf.push(ex.hash_algo);
        push_digest(buf, &ex.digest);
    }
}

fn pack_artifacts(buf: &mut Vec<u8>, artifacts: &[ArtifactPayload]) {
    crate::varint::push_varint(buf, artifacts.len() as u64);
    for art in artifacts {
        buf.push(art.os_id);
        buf.push(art.arch_id);
        buf.push(art.hash_algo);
        push_digest(buf, &art.digest);
    }
}

fn pack_hook_hashes(buf: &mut Vec<u8>, hook_hashes: &[HookHashPayload]) {
    crate::varint::push_varint(buf, hook_hashes.len() as u64);
    for sh in hook_hashes {
        push_str_field(buf, &sh.hook_type);
        buf.push(sh.hash_algo);
        push_digest(buf, &sh.digest);
    }
}

fn pack_patch_hash(buf: &mut Vec<u8>, patch_hash: Option<&(u8, Vec<u8>)>) {
    match patch_hash {
        Some((algo, digest)) => {
            debug_assert_eq!(
                digest.len(),
                32,
                "patch hash must be exactly 32 bytes to round-trip the fixed-width wire field"
            );
            buf.push(0x01);
            buf.push(*algo);
            buf.extend_from_slice(digest);
        }
        None => buf.push(0x00),
    }
}

/// Decodes a packed binary payload back into a [`PayloadData`], verifying the
/// trailing BLAKE3 digest over everything that precedes it.
///
/// # Errors
/// Returns [`Error::UnknownPayloadVersion`] when the leading version byte is not
/// [`PAYLOAD_VERSION`]; [`Error::PayloadTruncated`] when the payload is shorter
/// than a valid empty payload, truncated mid-field, or its trailing digest block
/// is not exactly 32 bytes; [`Error::NonCanonicalVarint`] for overlong varints;
/// [`Error::InvalidUtf8`] for string fields that are not UTF-8;
/// [`Error::UnknownHashAlgorithm`], [`Error::UnknownAttestationType`], or
/// [`Error::UnknownDepType`] when a type-id field carries an unrecognised value;
/// and [`Error::PayloadDigestMismatch`] when the trailing BLAKE3 digest does not
/// match the recomputed hash of the payload body.
pub fn unpack_payload(bytes: &[u8], line_number: usize) -> Result<PayloadData, Error> {
    if bytes.len() < 8 {
        return Err(Error::PayloadTruncated { line_number });
    }
    let mut cursor = 0;

    let version = read_u8(bytes, &mut cursor, line_number)?;
    if version != PAYLOAD_VERSION {
        return Err(Error::UnknownPayloadVersion {
            line_number,
            version,
            supported: PAYLOAD_VERSION,
        });
    }

    let logical_name_len = read_varint(bytes, &mut cursor, line_number)?;
    let logical_name = read_optional_string(bytes, &mut cursor, logical_name_len, line_number)?;
    let source_idx = read_varint(bytes, &mut cursor, line_number)?;
    let major = read_varint_u64(bytes, &mut cursor, line_number)?;
    let minor = read_varint_u64(bytes, &mut cursor, line_number)?;
    let patch = read_varint_u64(bytes, &mut cursor, line_number)?;

    let hash_count = read_varint(bytes, &mut cursor, line_number)?;
    let hashes = unpack_hashes(bytes, &mut cursor, hash_count, line_number)?;

    let feat_count = read_varint(bytes, &mut cursor, line_number)?;
    let features = unpack_features(bytes, &mut cursor, feat_count, line_number)?;

    let peer_count = read_varint(bytes, &mut cursor, line_number)?;
    let resolved_peers = unpack_resolved_peers(bytes, &mut cursor, peer_count, line_number)?;

    let dep_count = read_varint(bytes, &mut cursor, line_number)?;
    let deps = unpack_deps(bytes, &mut cursor, dep_count, line_number)?;

    let peer_req_count = read_varint(bytes, &mut cursor, line_number)?;
    let peer_requirements =
        unpack_peer_requirements(bytes, &mut cursor, peer_req_count, line_number)?;

    let tag_count = read_varint(bytes, &mut cursor, line_number)?;
    let platform_tags = unpack_platform_tags(bytes, &mut cursor, tag_count, line_number)?;

    let ex_count = read_varint(bytes, &mut cursor, line_number)?;
    let exports = unpack_exports(bytes, &mut cursor, ex_count, line_number)?;

    let art_count = read_varint(bytes, &mut cursor, line_number)?;
    let artifacts = unpack_artifacts(bytes, &mut cursor, art_count, line_number)?;

    let sh_count = read_varint(bytes, &mut cursor, line_number)?;
    let hook_hashes = unpack_hook_hashes(bytes, &mut cursor, sh_count, line_number)?;

    let patch_hash = unpack_patch_hash(bytes, &mut cursor, line_number)?;
    verify_payload_digest(bytes, cursor, line_number)?;

    Ok(PayloadData {
        logical_name,
        source_idx,
        major,
        minor,
        patch,
        hashes,
        features,
        resolved_peers,
        deps,
        peer_requirements,
        platform_tags,
        exports,
        artifacts,
        hook_hashes,
        patch_hash,
    })
}

// ---- low-level reading helpers -------------------------------------------------

/// Reads a single byte at `cursor`, advancing the cursor by one.
fn read_u8(bytes: &[u8], cursor: &mut usize, line_number: usize) -> Result<u8, Error> {
    let byte = bytes
        .get(*cursor)
        .copied()
        .ok_or(Error::PayloadTruncated { line_number })?;
    *cursor += 1;
    Ok(byte)
}

/// Ensures `need` more bytes are available from `cursor` onwards.
fn require_available(
    bytes: &[u8],
    cursor: usize,
    need: usize,
    line_number: usize,
) -> Result<(), Error> {
    match cursor.checked_add(need) {
        Some(end) if end <= bytes.len() => Ok(()),
        _ => Err(Error::PayloadTruncated { line_number }),
    }
}

/// Reads one varint, mapping the typed decode failure onto the payload errors.
fn read_varint_u64(bytes: &[u8], cursor: &mut usize, line_number: usize) -> Result<u64, Error> {
    crate::varint::decode_varint(bytes, cursor).map_err(|err| match err {
        crate::varint::VarintError::NonCanonical => Error::NonCanonicalVarint { line_number },
        _ => Error::PayloadTruncated { line_number },
    })
}

/// Reads one varint and converts it to a `usize`.
fn read_varint(bytes: &[u8], cursor: &mut usize, line_number: usize) -> Result<usize, Error> {
    let raw = read_varint_u64(bytes, cursor, line_number)?;
    usize::try_from(raw).map_err(|_| Error::PayloadTruncated { line_number })
}

/// Reads an 8-byte little-endian `u64` at `cursor`, advancing the cursor by 8.
fn read_le_u64(bytes: &[u8], cursor: &mut usize, line_number: usize) -> Result<u64, Error> {
    let chunk = cursor
        .checked_add(8)
        .and_then(|end| bytes.get(*cursor..end))
        .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
        .ok_or(Error::PayloadTruncated { line_number })?;
    *cursor += 8;
    Ok(u64::from_le_bytes(chunk))
}

/// Reads `len` bytes at `cursor`, advancing the cursor past them.
fn read_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
    line_number: usize,
) -> Result<&'a [u8], Error> {
    let slice = cursor
        .checked_add(len)
        .and_then(|end| bytes.get(*cursor..end))
        .ok_or(Error::PayloadTruncated { line_number })?;
    *cursor += len;
    Ok(slice)
}

/// Reads `len` bytes and strictly converts them to a `String`.
///
/// 0.x silently replaced invalid UTF-8 with an empty string, corrupting names
/// and feature tables; 1.0 rejects the payload.
fn read_string(
    bytes: &[u8],
    cursor: &mut usize,
    len: usize,
    line_number: usize,
) -> Result<String, Error> {
    let slice = read_slice(bytes, cursor, len, line_number)?;
    std::str::from_utf8(slice)
        .map(str::to_owned)
        .map_err(|_| Error::InvalidUtf8 {
            line_number,
            field: "string",
        })
}

/// Reads an optional string: `None` for a zero length, the decoded string otherwise.
fn read_optional_string(
    bytes: &[u8],
    cursor: &mut usize,
    len: usize,
    line_number: usize,
) -> Result<Option<String>, Error> {
    if len == 0 {
        return Ok(None);
    }
    read_string(bytes, cursor, len, line_number).map(Some)
}

// ---- section decoders ----------------------------------------------------------

fn unpack_hashes(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    line_number: usize,
) -> Result<Vec<HashPayload>, Error> {
    let mut hashes = Vec::new();
    for _ in 0..count {
        require_available(bytes, *cursor, 2, line_number)?;
        let algo_id = read_u8(bytes, cursor, line_number)?;
        if algo_id > 0x03 {
            return Err(Error::UnknownHashAlgorithm {
                line_number,
                algo_id,
            });
        }
        let hash_len = usize::from(read_u8(bytes, cursor, line_number)?);
        let digest = read_slice(bytes, cursor, hash_len, line_number)?.to_vec();

        let attest_type = read_u8(bytes, cursor, line_number)?;
        let attestation = unpack_attestation(bytes, cursor, attest_type, line_number)?;

        hashes.push(HashPayload {
            algo_id,
            digest,
            attestation,
        });
    }
    Ok(hashes)
}

fn unpack_attestation(
    bytes: &[u8],
    cursor: &mut usize,
    attest_type: u8,
    line_number: usize,
) -> Result<Attestation, Error> {
    match attest_type {
        0x00 => Ok(Attestation::None),
        0x01 => {
            let slice = read_slice(bytes, cursor, 32, line_number)?;
            let mut bundle = [0u8; 32];
            bundle.copy_from_slice(slice);
            Ok(Attestation::ExternalBundleSha256(bundle))
        }
        0x02 => {
            let builder_len = read_varint(bytes, cursor, line_number)?;
            let builder = read_string(bytes, cursor, builder_len, line_number)?;

            let source_len = read_varint(bytes, cursor, line_number)?;
            let source = read_string(bytes, cursor, source_len, line_number)?;

            Ok(Attestation::InlineSlsa(SlsaPredicate { builder, source }))
        }
        _ => Err(Error::UnknownAttestationType {
            line_number,
            type_id: attest_type,
        }),
    }
}

fn unpack_features(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    line_number: usize,
) -> Result<Vec<String>, Error> {
    let mut features = Vec::with_capacity(count.min(MAX_PREALLOC));
    for _ in 0..count {
        let str_len = read_varint(bytes, cursor, line_number)?;
        features.push(read_string(bytes, cursor, str_len, line_number)?);
    }
    Ok(features)
}

fn unpack_resolved_peers(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    line_number: usize,
) -> Result<Vec<PeerResolution>, Error> {
    let mut resolved_peers = Vec::new();
    for _ in 0..count {
        let p_name_len = read_varint(bytes, cursor, line_number)?;
        let p_name = read_string(bytes, cursor, p_name_len, line_number)?;

        require_available(bytes, *cursor, 9, line_number)?;
        let sat_cid = read_le_u64(bytes, cursor, line_number)?;
        let is_hoisted = read_u8(bytes, cursor, line_number)? == 0x01;

        resolved_peers.push(PeerResolution {
            peer_name: p_name,
            satisfied_by_content_id: sat_cid,
            is_hoisted_to_root: is_hoisted,
        });
    }
    Ok(resolved_peers)
}

fn unpack_deps(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    line_number: usize,
) -> Result<Vec<DepPayload>, Error> {
    let mut deps = Vec::new();
    for _ in 0..count {
        require_available(bytes, *cursor, 9, line_number)?;
        let content_id = read_le_u64(bytes, cursor, line_number)?;
        let dep_type = read_u8(bytes, cursor, line_number)?;
        if dep_type > 0x04 {
            return Err(Error::UnknownDepType {
                line_number,
                type_id: dep_type,
            });
        }

        let mut target_os = None;
        let mut target_arch = None;
        if dep_type == 0x04 {
            require_available(bytes, *cursor, 2, line_number)?;
            target_os = Some(read_u8(bytes, cursor, line_number)?);
            target_arch = Some(read_u8(bytes, cursor, line_number)?);
        }

        let req_count = read_varint(bytes, cursor, line_number)?;
        let mut req_indices = Vec::with_capacity(req_count.min(MAX_PREALLOC));
        for _ in 0..req_count {
            req_indices.push(read_varint(bytes, cursor, line_number)?);
        }
        deps.push(DepPayload {
            content_id,
            dep_type,
            target_os,
            target_arch,
            req_feat_indices: req_indices,
        });
    }
    Ok(deps)
}

fn unpack_peer_requirements(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    line_number: usize,
) -> Result<Vec<PeerReqPayload>, Error> {
    let mut peer_requirements = Vec::new();
    for _ in 0..count {
        let name_len = read_varint(bytes, cursor, line_number)?;
        let name = read_string(bytes, cursor, name_len, line_number)?;
        let range_len = read_varint(bytes, cursor, line_number)?;
        let range = read_string(bytes, cursor, range_len, line_number)?;
        let is_optional = read_u8(bytes, cursor, line_number)? == 0x01;
        peer_requirements.push(PeerReqPayload {
            peer_name: name,
            version_range: range,
            is_optional,
        });
    }
    Ok(peer_requirements)
}

fn unpack_platform_tags(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    line_number: usize,
) -> Result<Vec<PlatformTagPayload>, Error> {
    let mut platform_tags = Vec::new();
    for _ in 0..count {
        require_available(bytes, *cursor, 2, line_number)?;
        let os_id = read_u8(bytes, cursor, line_number)?;
        let arch_id = read_u8(bytes, cursor, line_number)?;
        platform_tags.push(PlatformTagPayload { os_id, arch_id });
    }
    Ok(platform_tags)
}

fn unpack_exports(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    line_number: usize,
) -> Result<Vec<ExportPayload>, Error> {
    let mut exports = Vec::new();
    for _ in 0..count {
        let id_len = read_varint(bytes, cursor, line_number)?;
        let identifier = read_string(bytes, cursor, id_len, line_number)?;
        let hash_algo = read_u8(bytes, cursor, line_number)?;
        let digest_len = usize::from(read_u8(bytes, cursor, line_number)?);
        let digest = read_slice(bytes, cursor, digest_len, line_number)?.to_vec();
        exports.push(ExportPayload {
            identifier,
            hash_algo,
            digest,
        });
    }
    Ok(exports)
}

fn unpack_artifacts(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    line_number: usize,
) -> Result<Vec<ArtifactPayload>, Error> {
    let mut artifacts = Vec::new();
    for _ in 0..count {
        require_available(bytes, *cursor, 3, line_number)?;
        let os_id = read_u8(bytes, cursor, line_number)?;
        let arch_id = read_u8(bytes, cursor, line_number)?;
        let hash_algo = read_u8(bytes, cursor, line_number)?;
        let digest_len = usize::from(read_u8(bytes, cursor, line_number)?);
        let digest = read_slice(bytes, cursor, digest_len, line_number)?.to_vec();
        artifacts.push(ArtifactPayload {
            os_id,
            arch_id,
            hash_algo,
            digest,
        });
    }
    Ok(artifacts)
}

fn unpack_hook_hashes(
    bytes: &[u8],
    cursor: &mut usize,
    count: usize,
    line_number: usize,
) -> Result<Vec<HookHashPayload>, Error> {
    let mut hook_hashes = Vec::new();
    for _ in 0..count {
        let hook_len = read_varint(bytes, cursor, line_number)?;
        let hook_type = read_string(bytes, cursor, hook_len, line_number)?;
        let hash_algo = read_u8(bytes, cursor, line_number)?;
        let digest_len = usize::from(read_u8(bytes, cursor, line_number)?);
        let digest = read_slice(bytes, cursor, digest_len, line_number)?.to_vec();
        hook_hashes.push(HookHashPayload {
            hook_type,
            hash_algo,
            digest,
        });
    }
    Ok(hook_hashes)
}

fn unpack_patch_hash(
    bytes: &[u8],
    cursor: &mut usize,
    line_number: usize,
) -> Result<Option<(u8, Vec<u8>)>, Error> {
    let patch_present = read_u8(bytes, cursor, line_number)?;
    if patch_present != 0x01 {
        return Ok(None);
    }

    require_available(bytes, *cursor, 33, line_number)?;
    let ph_algo = read_u8(bytes, cursor, line_number)?;
    let ph_digest = read_slice(bytes, cursor, 32, line_number)?.to_vec();
    Ok(Some((ph_algo, ph_digest)))
}

/// Verifies that the payload ends in exactly 32 bytes matching its BLAKE3 hash.
fn verify_payload_digest(bytes: &[u8], cursor: usize, line_number: usize) -> Result<(), Error> {
    let tail = bytes
        .get(cursor..)
        .and_then(|rest| <[u8; 32]>::try_from(rest).ok())
        .ok_or(Error::PayloadTruncated { line_number })?;
    let expected_hash = blake3::Hash::from_bytes(tail);
    if expected_hash != blake3::hash(&bytes[..cursor]) {
        return Err(Error::PayloadDigestMismatch { line_number });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_data() -> PayloadData {
        PayloadData {
            logical_name: None,
            source_idx: 0,
            major: 1,
            minor: 0,
            patch: 0,
            hashes: vec![],
            features: vec![],
            resolved_peers: vec![],
            deps: vec![],
            peer_requirements: vec![],
            platform_tags: vec![],
            exports: vec![],
            artifacts: vec![],
            hook_hashes: vec![],
            patch_hash: None,
        }
    }

    #[test]
    fn test_v10_version_byte() {
        let packed = pack_payload(&empty_data()).unwrap();
        assert_eq!(packed[0], PAYLOAD_VERSION);
    }

    #[test]
    fn test_v10_blake3_trailer() {
        let packed = pack_payload(&empty_data()).unwrap();
        assert_eq!(packed.len(), 48);
        let trailer = &packed[packed.len() - 32..];
        let expected = blake3::hash(&packed[..packed.len() - 32]);
        assert_eq!(trailer, expected.as_bytes());
    }

    #[test]
    fn test_v10_blake3_roundtrip() {
        let data = PayloadData {
            logical_name: Some("alias".to_string()),
            source_idx: 2,
            major: 3,
            minor: 1,
            patch: 4,
            hashes: vec![HashPayload {
                algo_id: 0x01,
                digest: vec![0xAA; 32],
                attestation: Attestation::None,
            }],
            features: vec!["f1".to_string()],
            resolved_peers: vec![],
            deps: vec![DepPayload {
                content_id: 42,
                dep_type: 0x00,
                target_os: None,
                target_arch: None,
                req_feat_indices: vec![],
            }],
            peer_requirements: vec![],
            platform_tags: vec![PlatformTagPayload {
                os_id: 0x01,
                arch_id: 0x01,
            }],
            exports: vec![ExportPayload {
                identifier: "./core".to_string(),
                hash_algo: 0x01,
                digest: vec![0xBB; 32],
            }],
            artifacts: vec![ArtifactPayload {
                os_id: 0x01,
                arch_id: 0x01,
                hash_algo: 0x03,
                digest: vec![0xCC; 32],
            }],
            hook_hashes: vec![],
            patch_hash: None,
        };
        let packed = pack_payload(&data).unwrap();
        let unpacked = unpack_payload(&packed, 0).unwrap();
        assert_eq!(unpacked.logical_name, Some("alias".to_string()));
        assert_eq!(unpacked.source_idx, 2);
        assert_eq!(unpacked.major, 3);
        assert_eq!(unpacked.hashes.len(), 1);
        assert_eq!(unpacked.features[0], "f1");
        assert_eq!(unpacked.deps[0].content_id, 42);
        assert_eq!(unpacked.platform_tags[0].os_id, 0x01);
        assert_eq!(unpacked.exports[0].identifier, "./core");
        assert_eq!(unpacked.artifacts[0].digest, vec![0xCC; 32]);
    }

    #[test]
    fn test_unpack_rejects_old_v07_payload() {
        let mut bad_payload = pack_payload(&empty_data()).unwrap();
        bad_payload[0] = 0x07;
        assert!(matches!(
            unpack_payload(&bad_payload, 1),
            Err(Error::UnknownPayloadVersion { .. })
        ));
    }

    #[test]
    #[allow(clippy::items_after_test_module)]
    fn test_pack_base_structure() {
        let data = PayloadData {
            logical_name: None,
            source_idx: 1,
            major: 1,
            minor: 0,
            patch: 0,
            hashes: vec![HashPayload {
                algo_id: 0x01,
                digest: vec![0xAA; 32],
                attestation: Attestation::None,
            }],
            features: vec![],
            resolved_peers: vec![],
            deps: vec![],
            peer_requirements: vec![],
            platform_tags: vec![],
            exports: vec![],
            artifacts: vec![],
            hook_hashes: vec![],
            patch_hash: None,
        };
        let packed = pack_payload(&data).unwrap();
        assert_eq!(packed[0], PAYLOAD_VERSION);
        let unpacked = unpack_payload(&packed, 0).unwrap();
        assert_eq!(unpacked.source_idx, 1);
        assert_eq!(unpacked.hashes.len(), 1);
    }

    #[test]
    fn test_pack_dep_content_id() {
        let data = PayloadData {
            logical_name: None,
            source_idx: 0,
            major: 1,
            minor: 0,
            patch: 0,
            hashes: vec![],
            features: vec![],
            resolved_peers: vec![],
            deps: vec![DepPayload {
                content_id: 12_345_678,
                dep_type: 0x00,
                target_os: None,
                target_arch: None,
                req_feat_indices: vec![],
            }],
            peer_requirements: vec![],
            platform_tags: vec![],
            exports: vec![],
            artifacts: vec![],
            hook_hashes: vec![],
            patch_hash: None,
        };
        let packed = pack_payload(&data).unwrap();
        let unpacked = unpack_payload(&packed, 0).unwrap();
        assert_eq!(unpacked.deps[0].content_id, 12_345_678);
        assert_eq!(unpacked.deps[0].dep_type, 0x00);
    }

    #[test]
    fn test_unpack_roundtrip() {
        let data = PayloadData {
            logical_name: None,
            source_idx: 0,
            major: 2,
            minor: 0,
            patch: 0,
            hashes: vec![HashPayload {
                algo_id: 0x01,
                digest: vec![0; 32],
                attestation: Attestation::None,
            }],
            features: vec!["sync".to_string()],
            resolved_peers: vec![],
            deps: vec![DepPayload {
                content_id: 99,
                dep_type: 0x01,
                target_os: None,
                target_arch: None,
                req_feat_indices: vec![0],
            }],
            peer_requirements: vec![],
            platform_tags: vec![],
            exports: vec![],
            artifacts: vec![],
            hook_hashes: vec![],
            patch_hash: None,
        };
        let packed = pack_payload(&data).unwrap();
        let unpacked = unpack_payload(&packed, 0).unwrap();
        assert_eq!(unpacked.features[0], "sync");
        assert_eq!(unpacked.deps[0].content_id, 99);
        assert!(matches!(unpacked.hashes[0].attestation, Attestation::None));
    }

    #[test]
    fn test_pack_hash_with_inline_slsa() {
        let data = PayloadData {
            logical_name: None,
            source_idx: 0,
            major: 1,
            minor: 0,
            patch: 0,
            hashes: vec![HashPayload {
                algo_id: 0x01,
                digest: vec![0xAA; 32],
                attestation: Attestation::InlineSlsa(SlsaPredicate {
                    builder: "github.com/actions".to_string(),
                    source: "git+https://github.com/pkg".to_string(),
                }),
            }],
            features: vec![],
            resolved_peers: vec![],
            deps: vec![],
            peer_requirements: vec![],
            platform_tags: vec![],
            exports: vec![],
            artifacts: vec![],
            hook_hashes: vec![],
            patch_hash: None,
        };
        let packed = pack_payload(&data).unwrap();
        let unpacked = unpack_payload(&packed, 0).unwrap();
        assert!(
            matches!(&unpacked.hashes[0].attestation, Attestation::InlineSlsa(p) if p.builder == "github.com/actions")
        );
    }

    #[test]
    fn test_pack_logical_name_and_peers() {
        let data = PayloadData {
            logical_name: Some("react-v18".to_string()),
            source_idx: 0,
            major: 18,
            minor: 0,
            patch: 0,
            hashes: vec![],
            features: vec![],
            resolved_peers: vec![PeerResolution {
                peer_name: "react".to_string(),
                satisfied_by_content_id: 99,
                is_hoisted_to_root: true,
            }],
            deps: vec![],
            peer_requirements: vec![],
            platform_tags: vec![],
            exports: vec![],
            artifacts: vec![],
            hook_hashes: vec![],
            patch_hash: None,
        };
        let packed = pack_payload(&data).unwrap();
        let unpacked = unpack_payload(&packed, 0).unwrap();
        assert_eq!(unpacked.logical_name, Some("react-v18".to_string()));
        assert_eq!(unpacked.resolved_peers[0].peer_name, "react");
        assert!(unpacked.resolved_peers[0].is_hoisted_to_root);
    }

    #[test]
    fn test_pack_peer_requirements() {
        let data = PayloadData {
            logical_name: None,
            source_idx: 0,
            major: 1,
            minor: 0,
            patch: 0,
            hashes: vec![],
            features: vec![],
            resolved_peers: vec![],
            deps: vec![],
            peer_requirements: vec![PeerReqPayload {
                peer_name: "react".to_string(),
                version_range: "^17.0.0".to_string(),
                is_optional: false,
            }],
            platform_tags: vec![],
            exports: vec![],
            artifacts: vec![],
            hook_hashes: vec![],
            patch_hash: None,
        };
        let packed = pack_payload(&data).unwrap();
        let unpacked = unpack_payload(&packed, 0).unwrap();
        assert_eq!(unpacked.peer_requirements.len(), 1);
        assert_eq!(unpacked.peer_requirements[0].peer_name, "react");
        assert_eq!(unpacked.hook_hashes.len(), 0);
        assert!(unpacked.patch_hash.is_none());
    }

    #[test]
    fn test_roundtrip_peer_reqs_and_tags() {
        let data = PayloadData {
            logical_name: None,
            source_idx: 0,
            major: 1,
            minor: 0,
            patch: 0,
            hashes: vec![],
            features: vec![],
            resolved_peers: vec![],
            deps: vec![],
            peer_requirements: vec![
                PeerReqPayload {
                    peer_name: "react".to_string(),
                    version_range: "^17.0.0".to_string(),
                    is_optional: false,
                },
                PeerReqPayload {
                    peer_name: "react-dom".to_string(),
                    version_range: String::new(),
                    is_optional: true,
                },
            ],
            platform_tags: vec![
                PlatformTagPayload {
                    os_id: 0x01,
                    arch_id: 0x01,
                },
                PlatformTagPayload {
                    os_id: 0x02,
                    arch_id: 0x02,
                },
            ],
            exports: vec![],
            artifacts: vec![],
            hook_hashes: vec![],
            patch_hash: None,
        };
        let packed = pack_payload(&data).unwrap();
        let unpacked = unpack_payload(&packed, 0).unwrap();
        assert_eq!(unpacked.peer_requirements.len(), 2);
        assert_eq!(unpacked.peer_requirements[0].peer_name, "react");
        assert_eq!(unpacked.peer_requirements[0].version_range, "^17.0.0");
        assert!(!unpacked.peer_requirements[0].is_optional);
        assert_eq!(unpacked.platform_tags.len(), 2);
        assert_eq!(unpacked.platform_tags[0].os_id, 0x01);
        assert_eq!(unpacked.platform_tags[1].arch_id, 0x02);
    }

    #[test]
    fn test_pack_script_hashes() {
        let data = PayloadData {
            logical_name: None,
            source_idx: 0,
            major: 1,
            minor: 0,
            patch: 0,
            hashes: vec![],
            features: vec![],
            resolved_peers: vec![],
            deps: vec![],
            peer_requirements: vec![],
            platform_tags: vec![],
            exports: vec![],
            artifacts: vec![],
            hook_hashes: vec![HookHashPayload {
                hook_type: "postinstall".to_string(),
                hash_algo: 0x03,
                digest: vec![0xAA; 32],
            }],
            patch_hash: None,
        };
        let packed = pack_payload(&data).unwrap();
        let unpacked = unpack_payload(&packed, 0).unwrap();
        assert_eq!(unpacked.hook_hashes.len(), 1);
        assert_eq!(unpacked.hook_hashes[0].hook_type, "postinstall");
        assert_eq!(unpacked.hook_hashes[0].hash_algo, 0x03);
        assert_eq!(unpacked.hook_hashes[0].digest, vec![0xAA; 32]);
        assert!(unpacked.patch_hash.is_none());
    }

    #[test]
    fn test_pack_patch_hash_present() {
        let data = PayloadData {
            logical_name: None,
            source_idx: 0,
            major: 1,
            minor: 0,
            patch: 0,
            hashes: vec![],
            features: vec![],
            resolved_peers: vec![],
            deps: vec![],
            peer_requirements: vec![],
            platform_tags: vec![],
            exports: vec![],
            artifacts: vec![],
            hook_hashes: vec![],
            patch_hash: Some((0x03, vec![0xBB; 32])),
        };
        let packed = pack_payload(&data).unwrap();
        let unpacked = unpack_payload(&packed, 0).unwrap();
        assert_eq!(unpacked.patch_hash.as_ref().map(|(a, _)| *a), Some(0x03));
        assert_eq!(unpacked.patch_hash.as_ref().map(|(_, d)| d.len()), Some(32));
    }

    #[test]
    fn test_pack_patch_hash_absent() {
        let packed = pack_payload(&empty_data()).unwrap();
        let unpacked = unpack_payload(&packed, 0).unwrap();
        assert!(unpacked.patch_hash.is_none());
    }
}
