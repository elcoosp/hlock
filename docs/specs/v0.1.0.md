# HLOCK Specification (Hybrid Lockfile Format)
**Version:** 1.0
**File Extension:** `.hlock`

## 1. Design Philosophy
HLOCK guarantees one package per line. This ensures that adding, removing, or updating a package results in exactly one line changing in `git diff`. However, it eliminates JSON/TOML syntax bloat by compressing all machine-readable metadata (versions, hashes, dependency arrays) into a dense binary payload attached to each line.

## 2. File Structure
The file MUST be encoded in UTF-8. Lines MUST be separated by `\n` (LF). There are no block structures, indentation, or trailing commas.

```text
<package_name_1>\t<payload_1>
<package_name_2>\t<payload_2>
...
```

*   `<package_name>`: A UTF-8 string. MUST NOT contain tab (`\t`) or newline (`\n`) characters.
*   `\t`: A single Tab character acts as the delimiter. (Tabs are preferred over spaces because package names never contain tabs, preventing parsing ambiguity).
*   `<payload>`: A Base64URL encoded string representing the binary metadata of the package.

## 3. The Binary Payload
Before Base64URL encoding, the payload is a compact byte array. All multi-byte integers are encoded using **Unsigned LEB128 (Varint)** to minimize space. 

The binary array has the following sequential structure:

| Field | Type | Size | Description |
| :--- | :--- | :--- | :--- |
| `Semver` | 3x Varint | 1-9 bytes | `Major`, `Minor`, `Patch`. (e.g., `4.17.21` is stored as `0x04`, `0x11`, `0x15` taking 3 bytes). |
| `Hash` | Bytes | 16 bytes | The first 16 bytes (128 bits) of the package's integrity hash (e.g., SHA-256 truncated to 128 bits). 128 bits provides cryptographic collision resistance sufficient for download verification while halving the size of standard SHA-256 strings. |
| `DepCount`| Varint | 1+ bytes | The number of direct dependencies this package has. |
| `DepIndices`| `DepCount` x Varint | `DepCount` bytes+| **The ultimate optimization.** Instead of storing dependency names as strings, this stores the **0-based line index** of the dependency within the HLOCK file. |

## 4. Dependency Index Resolution
Because the file is sorted alphabetically by `<package_name>`, the parser assigns an implicit index to every line as it reads the file top-to-bottom.
*   Line 0 = `@types/node`
*   Line 1 = `axios`
*   Line 2 = `lodash`

If `axios` depends on `lodash`, `axios`'s payload does not contain the string "lodash". It simply contains the Varint `2`. 
*Note: Because of alphabetical sorting, a package may depend on a package that appears *later* in the file (e.g., `aardvark` depends on `zebra`). The parser MUST read the entire file into memory to build an index map before resolving dependency trees.*

## 5. Base64URL Encoding Rules
To ensure the binary payload does not contain tabs, newlines, or unprintable characters (which would ruin the line format), it is encoded using Base64URL as defined in [RFC 4648 §5].
*   No padding (`=` characters are stripped).
*   `+` is replaced with `-`
*   `/` is replaced with `_`

---

## 6. Example

Let's assume a project with three packages:
1. `axios` (v1.6.0) depends on nothing.
2. `lodash` (v4.17.21) depends on nothing.
3. `react` (v18.2.0) depends on `lodash` (Index 1).

### Step 1: Construct Binary Payloads

**axios payload:**
*   Semver: `[1, 6, 0]` (3 bytes)
*   Hash: `[16 random bytes]` (16 bytes)
*   DepCount: `[0]` (1 byte)
*   *Total: 20 bytes.*

**react payload:**
*   Semver: `[18, 2, 0]` (3 bytes)
*   Hash: `[16 random bytes]` (16 bytes)
*   DepCount: `[1]` (1 byte)
*   DepIndices: `[1]` (pointing to lodash) (1 byte)
*   *Total: 21 bytes.*

### Step 2: Base64URL Encode
*(Using fake hashes for demonstration)*
*   `axios` 20 bytes -> `AQYAAAAAAAAAAAAAAAAAAAAAAAAAA` (28 chars)
*   `lodash` 20 bytes -> `EBERAAAAAAAAAAAAAAAAAAAAAAAAAA` (28 chars)
*   `react` 21 bytes -> `EgIAAAAAAAAAAAAAAAAAAAAAAAAAAQ` (28 chars)

### Step 3: Final `.hlock` File Output

```text
axios	AQYAAAAAAAAAAAAAAAAAAAAAAAAAA
lodash	EBERAAAAAAAAAAAAAAAAAAAAAAAAAA
react	EgIAAAAAAAAAAAAAAAAAAAAAAAAAAQ
```

---

## 7. Why this is the Ultimate Middle Ground

1. **`git diff` Friendly:** If `react` updates to 18.2.1, the Base64 string changes slightly, but it is strictly confined to the `react` line. No other lines shift.
2. **Human Searchable:** A developer can run `grep "react" hlock.lock` and it works instantly. They can visually see what packages are in the project just by looking at the left side of the lines.
3. **Extreme Machine Compression:** 
   * Versions take 3 bytes instead of ~10 chars (`"18.2.0"`).
   * Hashes take 16 bytes instead of 64 chars (SHA-256 hex).
   * Dependencies take **1 byte** per dependency, instead of 10-50 bytes per string name.
4. **Fast Parsing:** The machine reads a line, splits on `\t`, decodes the Base64 chunk into a pre-allocated 20-50 byte buffer, and reads sequential Varints. There is zero string allocation for dependency names during the parsing phase. It will parse millions of packages a second.
