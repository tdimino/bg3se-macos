# ls::STDString ABI Layout (ARM64 macOS)

**Platform:** macOS ARM64
**Discovered:** 2026-04-01 (Ghidra decompilation)
**Status:** ✅ Fully verified — safe to construct on stack for SSO strings

## Layout (16 bytes)

`ls::STDString` = `std::basic_string<char, std::char_traits<char>, ls::StringAllocator<char>>`

Standard libc++ `__compressed_pair` layout with Larian's custom allocator.

### Short String (SSO) — strings <= 14 chars

```
Offset 0x00-0x0E: char data[15]    (inline buffer, 14 chars + NUL)
Offset 0x0F:      uint8_t           (bit 7 = is_long=0, bits 0-6 = size)
```

### Long String — strings > 14 chars

```
Offset 0x00: char*    data       (heap pointer via ls::MemoryManager)
Offset 0x08: uint32_t size       (string length)
Offset 0x0C: uint32_t cap_flag   (bit 31 = is_long=1, bits 0-30 = capacity)
```

### Discriminator

`is_long` = bit 7 of byte 0x0F (sign bit check: `*(char*)(str + 0xF) < 0`).

## C Struct Definition

```c
typedef struct {
    union {
        struct {  // Long string
            char*    data;      // 0x00
            uint32_t size;      // 0x08
            uint32_t cap_flag;  // 0x0C (bit 31 = is_long, bits 0-30 = capacity)
        } l;
        struct {  // Short string (SSO)
            char     data[15];  // 0x00-0x0E
            uint8_t  size_flag; // 0x0F (bit 7 = is_long, bits 0-6 = size)
        } s;
    };
} LSSTDString;  // 16 bytes
```

## Safe Stack Construction

**For strings <= 14 chars (SSO — no allocation):**
```c
static inline void ls_stdstring_init_short(LSSTDString* s, const char* str, size_t len) {
    memset(s, 0, sizeof(*s));
    memcpy(s->s.data, str, len);
    s->s.data[len] = '\0';
    s->s.size_flag = (uint8_t)len;  // bit 7 clear = short mode
}
```

**For strings > 14 chars — MUST use game's constructor:**
```c
typedef void (*STDStringCtorFn)(void* this_, const char* str);
static STDStringCtorFn g_stdstring_ctor = NULL;
// Resolve at init: g_stdstring_ctor = (STDStringCtorFn)(base + 0x0651fb60);

LSSTDString path_str;
memset(&path_str, 0, sizeof(path_str));
g_stdstring_ctor(&path_str, file_path);
// Now pass &path_str where STDString& is expected
```

**WARNING:** Do NOT use raw `malloc` for long strings. `ls::StringAllocator` routes
through `ls::MemoryManager` — game's free won't recognize malloc'd pointers.

## Key Addresses

| Function | Address | Notes |
|----------|---------|-------|
| `ls::STDString(const char*)` | `0x10651fb60` | Constructor from C string |
| `ls::STDString(const StringView&)` | `0x10651fdfc` | Constructor from StringView |
| `ls::STDString(const STDString&)` | `0x10651ff18` | Copy constructor |
| `ls::STDString::Compare(const StringView&)` | `0x1065202a8` | Comparison |
| `ls::MemoryManager` global | `0x108aefa98` | Custom allocator backing |

## Related Types

| Type | Size | Notes |
|------|------|-------|
| `ls::FixedString` | 4 bytes | Index into GlobalStringTable (NOT an STDString) |
| `ls::_StringView<char>` | 16 bytes | `(const char* data, uint32_t length)` — two registers on ARM64 |
| `ls::ScratchString` | varies | Stack-allocated buffer, different semantics |

## Decompilation Evidence

SSO threshold check from `ls::STDString::STDString(const char*)`:
```c
if (uVar1 < 0xf) {
    // SSO path: memmove into inline buffer, set byte 0xF = length
    memmove(param_1, param_2, uVar1);
    *(char*)((long)param_1 + 0xf) = (char)uVar1;
} else {
    // Long path: allocate via MemoryManager, set is_long bit
    uVar3 = (uVar1 | 0xf);
    ptr = _malloc(uVar3 + 1);
    *param_1 = ptr;
    *(uint*)(param_1 + 0xc) = uVar3 | 0x80000000;  // capacity + is_long flag
}
```

## Impact: PlayExternalSound

PlayExternalSound can now be re-enabled using this construction pattern. For typical
file paths (>14 chars), use the game's constructor at `0x10651fb60`. For short paths,
use SSO stack construction.

## References

- RTTI string: `0x1081e64d4` — full STDString layout descriptor
- `ls::Path::Normalize(STDString&)` at `0x10651a7e8` — confirms access pattern
