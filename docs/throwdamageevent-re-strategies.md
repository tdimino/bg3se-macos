# ThrowDamageEvent ARM64 RE Strategies

**Context:** Finding `esv::StatsSystem::ThrowDamageEvent` in stripped BG3 ARM64 Mach-O binary. Ghidra's xref resolution fails on adrp+add page-relative references to TypeId globals, leaving us unable to trace forward through component creation.

**Last Updated:** 2026-04-03

---

## 1. Manual ADRP+ADD Resolution

**Status:** Actionable now. Ghidra's limitation is a known issue (#6891). We can compute addresses manually.

### How It Works
- ADRP: loads the 4KB page address (21-bit signed offset << 12)
- ADD: adds the 12-bit offset within that page
- Combined: resolves to absolute address

### Concrete Technique
1. **Locate the ADRP+ADD pair** in ThrowDamageEvent (we have the address)
2. **Extract instruction bytes** from hex view
3. **Compute page address:**
   ```
   // ADRP encoding: bits [23:5] = 21-bit signed offset
   int adrp_instr = 0x__000090;  // your instruction bytes
   int offset = (adrp_instr >> 5) & 0x1fffff;
   // Sign-extend from 21 bits
   if (offset & 0x100000) offset |= 0xffe00000;
   int64_t page_addr = (instruction_addr & ~0xfff) + (offset << 12);
   ```
4. **Add the 12-bit offset from ADD:**
   ```
   int add_instr = 0x_________;  // second instruction
   int page_offset = (add_instr & 0xfff);  // lowest 12 bits
   int64_t final_addr = page_addr + page_offset;
   ```

### Tools to Implement This
- **Quick & dirty:** Write a Python script using `capstone` or `keystone` to decode the two instructions, extract operands, compute address
- **In Ghidra:** Use the Script Console with ARM64-specific instruction parsing (Ghidra's API has `Instruction.getOpObjects()`)
- **Reference:** Stack Overflow Q#15418 has working C code for adrp+add calculation

### Why This Works
- Doesn't rely on Ghidra's xref resolver
- Gets you the **exact memory address** of the TypeId global
- From there, trace what reads/writes that address (backward xref from that memory location)

---

## 2. Forward-Trace from Component Creation

**Status:** New angle. If we find where TypeId globals are used, we can find functions that **create** components.

### Approach
1. **Search for `new` / `malloc` call patterns** in the binary
   - ARM64: allocator calls are typically indirect through registers or direct BL/BLR
   - Look for consistent prologue: save callee-regs, call allocator, setup this pointer
2. **Look for the EntityDamagedEventOneFrameComponent constructor call**
   - Pattern: `BL <alloc>` → `MOV X0, <size>` → `MOV X1, <vtable>`
   - OR: Inline construction (less likely for Larian's ECS)
3. **Backtrace from the component address to the function that creates it**
   - If TypeId has a global address (via ADRP+ADD), see what functions read that address
   - Narrow to functions in the expected address range (StatsSystem code section)

### Tools
- **Ghidra Script:** Search for memory references to a specific address, filter by function
  ```python
  # Find all xrefs to the TypeId global (once you compute its address)
  from ghidra.program.model.address import Address
  target = Address("0x...")
  for xref in getReferencesTo(target):
      print(f"Read by: {xref.getFromAddress()}")
  ```
- **Binary Ninja:** Has better xref resolution for memory references than Ghidra ARM64

---

## 3. Signature-Based Pattern Matching

**Status:** Practical. BG3's ECS is consistent; ThrowDamageEvent has a recognizable signature.

### Pattern Recognition Strategy
1. **Common ECS pattern in ThrowDamageEvent:**
   - Prologue (save registers)
   - Load this pointer (adrp+add to StatsSystem)
   - Load TypeId global (adrp+add — **your blocker**)
   - Allocate component (call or inline)
   - Initialize fields
   - Epilogue (return)

2. **Build a byte signature for the allocation step:**
   - What's the exact sequence of instructions that allocates an EntityDamagedEventOneFrameComponent?
   - Example: `MOV X0, #sizeof(Component)` → `BL allocator` → `ADRP/ADD vtable`
   - Scan the binary for that exact byte pattern

3. **Tools for signature scanning:**
   - **Binary Ninja's Pattern Search:** GUI-based, easy to build visual patterns
   - **yara:** Write a YARA rule for the pattern, scan the entire binary
   - **Capstone + script:** Disassemble sections, match instruction sequences programmatically

### Reference
- Olivia Gallucci's "Signature-based Analysis for Reversing" (2025) covers this exact technique
- Signature scanning is standard for reversing heavily optimized binaries where control flow is unclear

---

## 4. Control Flow / Data Flow Analysis

**Status:** Advanced, but more reliable than single patterns.

### Technique
1. **Start from a known function that calls ThrowDamageEvent**
   - We may not know this directly, but: find DealDamage, find what calls it
   - Work backward from Osi.DealDamage (which we can hook easily)
2. **Trace the data flow:**
   - What parameters are passed to ThrowDamageEvent?
   - Where do those parameters come from?
   - A function that **constructs** EntityDamagedEventOneFrameComponent likely does similar data flow
3. **In Ghidra:**
   - Use Data Flow Graph analysis (right-click function → Show Data Dependencies)
   - Follow parameter chains backward
   - Look for functions that initialize component fields

### Why This Works
- We don't need xrefs to globals if we trace **data flow**
- Tells us not just the function, but the context of how it's called

---

## 5. Disassembly Inspection + Manual Annotation

**Status:** Tedious but guarantees results.

### Step-by-Step
1. **Open ThrowDamageEvent in Ghidra**
2. **Manually walk through every instruction**
3. **Note all adrp+add sequences** (for globals)
4. **For each pair, manually compute the target address** (see Strategy #1)
5. **Add a comment to the code:**
   ```
   ADRP X8, 0xabcd  ; page addr = 0x1000d000
   ADD X8, X8, #0x234  ; final addr = 0x1000d234 → TypeId_EntityDamagedEvent
   ```
6. **Search the binary for reads/writes to 0x1000d234**
7. **Identify the allocation function**

### Tools
- **Ghidra script to mark addresses:**
  ```python
  createMemoryBookmark(Address("0x..."), "TypeId Reference", "Computed ADRP+ADD target")
  ```

---

## 6. Cross-Reference with Windows Binary

**Status:** Highest confidence approach.

### The Idea
- Windows BG3SE binary is NOT stripped
- Function names are visible → find ThrowDamageEvent in Windows symbols
- Reverse-engineer the logic flow
- Apply the same logic to macOS (same codebase)
- In macOS, we now know **what to look for** (specific instruction patterns, data structure layouts)

### How
1. **Get Windows BG3SE binary** (Steam version or extracted from Windows VM)
2. **Open in Ghidra, find esv::StatsSystem::ThrowDamageEvent** (symbols are there)
3. **Document:**
   - What it reads
   - What it writes
   - What functions it calls
   - Component field initialization order
4. **Annotate macOS Ghidra session with these findings**
5. **Recognize the same patterns in ARM64** (much easier once you know what to look for)

### Tools
- **Ghidra:** Open Windows x86-64 binary in a second project
- **Binary Ninja:** Can diff binaries across architectures

---

## 7. Symbolic Debugging (If Possible)

**Status:** Limited but worth noting.

- If you can attach a debugger to BG3 on macOS, set a breakpoint at a known function that calls ThrowDamageEvent
- Step through the code, watch register values
- When you hit the adrp+add, read the resulting address from the register
- **This gives you the exact memory address of the TypeId global**
- From there, use xref searching (Strategy #2)

### Requirements
- Debugging symbols (we don't have)
- Or, manually construct a minimal reproducer that triggers ThrowDamageEvent

---

## Recommended Order of Attack

1. **Compute the ADRP+ADD addresses manually** (Strategy #1)
   - Takes 5–10 minutes, high confidence
   - Immediately unblocks xref searching

2. **Use Ghidra's xref-to-address script** (part of Strategy #2)
   - Once you have the computed address, find all reads/writes to it
   - Filter by function and address range

3. **Cross-reference with Windows binary** (Strategy #6)
   - Confirm the function logic matches
   - Verify component field layouts

4. **If still blocked:** Signature scanning (Strategy #3)
   - Build a pattern for the component allocation
   - Scan the binary

5. **Last resort:** Manual disassembly inspection (Strategy #5)
   - Time-consuming but guaranteed to work

---

## Why Ghidra's ADRP Xref Resolution Fails

**Root cause:** Ghidra's ARM64 analysis doesn't compute page-relative references in the same way x86-64 RIP-relative references work. The issue is tracked in [Ghidra #6891](https://github.com/NationalSecurityAgency/ghidra/issues/6891).

**Workaround:** Manual computation (Strategy #1) or switching to **Binary Ninja** (which has superior ARM64 support, particularly for Apple platforms).

---

## Tools to Consider Installing

- **Binary Ninja:** Superior ARM64 + macOS support (~$150/year or cloud edition)
- **Hopper Disassembler:** Native macOS, strong ARM64 analysis
- **capstone + Python:** DIY ADRP+ADD calculator (~30 lines of code)

---

## References

1. **ARM Instruction Set:**
   - https://developer.arm.com/documentation/ddi0602/2025-12/Base-Instructions/ADRP--Form-PC-relative-address-to-4KB-page-
   - https://belkadan.com/blog/2022/05/ARM64-Relative-References/

2. **Ghidra ARM64 Issues:**
   - https://github.com/NationalSecurityAgency/ghidra/issues/6891
   - https://github.com/NationalSecurityAgency/ghidra/issues/9017

3. **Signature-Based Analysis:**
   - https://oliviagallucci.com/signature-based-analysis-for-reversing/

4. **Mach-O & ARM64 RE:**
   - https://oliviagallucci.com/the-anatomy-of-a-mach-o-structure-code-signing-and-pac/
   - https://medium.com/@andrewss112/reverse-engineering-mach-o-arm64-d33f6373ed85

5. **Practical ADRP+ADD Calculation:**
   - https://reverseengineering.stackexchange.com/questions/15418/getting-function-address-by-reading-adrp-and-add-instruction-values

---

## Next Steps

1. **Pick Strategy #1** (ADRP+ADD manual computation)
2. **Write a 30-line Python script** to compute target address from instruction bytes
3. **Run it on the adrp+add pair in ThrowDamageEvent**
4. **Use Ghidra script to find xrefs to that computed address**
5. **Report back with findings**

This should unblock you within the hour.
