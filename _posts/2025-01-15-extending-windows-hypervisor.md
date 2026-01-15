---
layout: default
title: "Extending the Windows Hypervisor: A Deep Dive into VTL-1 Code Injection"
date: 2025-01-15
categories: [security, uefi, hypervisor, windows-internals]
excerpt: "A technical walkthrough of building a UEFI driver that patches Windows Hyper-V at boot time, injecting custom code into the hypervisor's VM exit handler to gain VTL-1 level execution."
---

# Extending the Windows Hypervisor: A Deep Dive into VTL-1 Code Injection

**Published: January 15, 2025**  
**Project: [ExtendedHv on GitHub](https://github.com/0xzczxy/ZczxyPkg)**

---

## Introduction

Windows 11 introduced Virtual Trust Levels (VTLs) as part of its security architecture, with VTL-1 representing the hypervisor layer—the highest privilege level in the system. This sits above even kernel mode (VTL-0), controlling virtualization and enforcing security policies through Windows Hypervisor (Hyper-V).

What if we could inject our own code into this hypervisor layer? That's exactly what **ExtendedHv** does—a UEFI runtime driver that patches Windows Hyper-V during the boot process to inject position-independent code into the VM exit handler.

> **⚠️ Important:** This project is purely educational and demonstrates advanced low-level programming concepts. It should never be deployed in production environments and may cause system instability.

---

## Motivation

This project was born from curiosity about how Windows boot processes work and how the hypervisor gets loaded. I wanted to understand:

- How does `winload.efi` prepare and load the hypervisor?
- Can we intercept this process at the UEFI level?
- What does the hypervisor's VM exit handler look like?
- Is it possible to inject position-independent code that survives the transition from UEFI to the running hypervisor?

The result is a working proof-of-concept that demonstrates all of these concepts.

---

## Architecture Overview

### The Boot Chain

```
Firmware (UEFI)
    ↓
Boot Manager (bootmgfw.efi)
    ↓
Windows Boot Loader (winload.efi)
    ↓ [Our Hook Point]
Hypervisor (hvix64.exe / hvax64.exe)
    ↓
Windows Kernel (ntoskrnl.exe)
```

ExtendedHv operates at the UEFI level and hooks into `winload.efi` functions to intercept hypervisor loading.

### Control Flow

The driver follows this execution path:

1. **DriverEntry** → Install hooks on UEFI services
2. **GetVariable Hook** → Detect when `winload.efi` is running
3. **BlImgAllocateImageBuffer Patch** → Extend memory allocation for our payload
4. **BlLdrLoadImage Patch** → Inject code when `hv.exe` loads
5. **VM Exit Handler Patch** → Redirect hypervisor calls to our code

![Architecture Diagram](../assets/extendedhv-architecture.png)
*[Screenshot: Architecture diagram showing hook chain]*

---

## Technical Deep Dive

### Challenge 1: Detecting winload.efi

The first challenge was identifying when `winload.efi` is executing. I hooked the UEFI `GetVariable` service and scanned backward from the return address to find the PE signature:

```c
// Scan for DOS stub signature
while (CompareMem((VOID*)returnAddress, 
      "This program cannot be run in DOS mode", 38) != 0) {
    returnAddress--;
}

// DOS stub is at offset 0x4E from PE base
moduleBase = returnAddress - 0x4E;
```

Once detected, I locate two critical exported functions using PE parsing:
- `BlImgAllocateImageBuffer` - allocates memory for loaded images
- `BlLdrLoadImage` - loads PE images during boot

### Challenge 2: Patching the VM Exit Handler

The hypervisor's VM exit handler is called every time the VM needs to exit to handle privileged operations. I needed to:

1. **Find the call instruction** - pattern scanning within the hypervisor image
2. **Calculate relative offset** - maintain proper control flow
3. **Redirect the call** - patch to jump to our code
4. **Chain to original** - ensure normal operation continues

For Intel (hvix64.exe):
```c
// Pattern: E8 ? ? ? ? E9 ? ? ? ? 74
//          ^^ relative call
```

For AMD (hvax64.exe):
```c
// Pattern: E8 ? ? ? ? 48 89 04 24 E9
//          ^^ relative call
```

![Disassembly View](../assets/extendedhv-patch.png)
*[Screenshot: IDA/Ghidra showing patched call instruction]*

The patch process:
1. Read current 32-bit relative offset
2. Calculate absolute address of original handler
3. Write new offset pointing to our payload
4. Store offset back to original in our payload's global variable

### Challenge 3: Memory Allocation Extension

The hypervisor is loaded with a specific memory allocation. To fit our payload, I patched `BlImgAllocateImageBuffer` to detect hypervisor allocations and extend them:

```c
if (attributes == ATTRIBUTE_HV_IMAGE && !gExtendedAllocation) {
    imageSize += PAYLOAD_SIZE;
    memoryType = MEMORY_ATTRIBUTE_RWX;  // Read-Write-Execute
    gExtendedAllocation = TRUE;
}
```

### Challenge 5: Adding a PE Section

The hypervisor PE needs a new section to hold our code. I implemented PE manipulation to:
- Calculate proper virtual addresses with alignment
- Update section count in PE headers
- Update `SizeOfImage` in optional header
- Set appropriate section characteristics (RWX)

![PE Section View](../assets/extendedhv-section.png)
*[Screenshot: PE viewer showing new .zczxyhc section]*

---

### Challenge 6: Position-Independent Payload

The hypervisor runs in a completely different address space than UEFI. Our injected code must be:
- **Position-independent** - no absolute addresses
- **Self-contained** - no external dependencies
- **Compact** - fits within extended allocation

I solved this by compiling a separate payload with specific compiler flags:

```makefile
CFLAGS := -fPIC -fno-plt -fvisibility=hidden \
          -fno-stack-protector -mno-red-zone \
          -nostdlib -nostartfiles -nodefaultlibs
```

The payload uses a custom linker script to ensure a known memory layout:

```
SECTIONS {
  . = 0x0;
  
  .data.global : ALIGN(8) {
    *(.data.global)  /* G_original_offset_from_hook at 0x0 */
  }
  
  .text.function : ALIGN(8) {
    *(.text.function)  /* hooked_vmexit_handler at 0x10 */
  }
}
```

This guarantees our global offset variable is at position 0x0 and our handler function starts at 0x10.

## The Payload: Intercepting CPUID

The injected payload demonstrates hypervisor-level code execution by intercepting CPUID instructions the code is architecture specific but an example handler looks like this:

```c
uint64_t __attribute__((ms_abi)) vmexit_handler(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4) {
  if (!g_has_been_called) {
    g_has_been_called = 1;
    serial_write("[+] Intel VM-Exit Handler Initialized.\n");
  }

  //
  // Read through vmread(VMCS_EXIT_REASON)
  // 
  uint64_t exit_reason = vmread(VMCS_EXIT_REASON);

  //
  // Check if we this was caused by a cpuid
  // 
  if (exit_reason == VMX_EXIT_REASON_EXECUTE_CPUID) {
    context_t *ctx = *(context_t**)a1;

    //
    // Check if rax is set to our special value
    // 
    if (ctx->rax == 0xDEADBEEFDEADBEEFull) {
      serial_write("[*] CPUID Called with 0xDEADBEEFDEADBEEF!\n");

      //
      // custom return value: zczxyhc\0 in little endian
      // 
      ctx->r8 = 0x00636879787A637Aull;
    }
  }

  //
  // Forward
  //
  original_vmexit_handler_t original = (original_vmexit_handler_t)(
    (uint64_t)vmexit_handler + G_original_offset_from_hook
  );
  return original(a1, a2, a3, a4);
}
```

This creates a hypercall interface—usermode code can execute CPUID with our magic value and receive our signature, proving hypervisor-level code execution.

![CPUID Test](../assets/extendedhv-test.png)
*[Screenshot: Test program showing custom CPUID result]*

---

## Build System

The project uses a unique two-stage build:

1. **Payload compilation** (Linux/WSL2):
   - Compile position-independent payloads for Intel and AMD
   - Extract raw binary from ELF files
   - Convert to C header arrays with Python script

2. **Driver compilation** (EDK II):
   - Include generated headers
   - Build UEFI driver with embedded payloads
   - Link everything together

This separation ensures the payload has no UEFI dependencies while allowing the main driver to use full UEFI libraries.

---

## Testing & Debugging

Serial port debugging was essential for this project. The driver outputs detailed logs over COM1 (0x3F8):

```
[+] Extended Hyper-V Driver v1.0
[+] ExitBootServices hook installed
[+] GetVariable hook installed
[+] Found potential winload.efi
[+] Found export 'BlImgAllocateImageBuffer'
[+] Found export 'BlLdrLoadImage'
[+] Intel Architecture Detected
[+] Patch hv*x64.exe successfully
```

Serial debugging allowed me to trace execution from UEFI all the way through hypervisor loading.

![Serial Output](../assets/extendedhv-serial.png)
*[Screenshot: Serial console showing boot logs]*

---

## Challenges Encountered

### Intel vs AMD Differences

The two hypervisor implementations have completely different calling conventions and structures:
- Intel uses more parameters and has a more complex context structure
- AMD's implementation has changed less over Windows versions
- Pattern signatures are architecture-specific

### Windows Version Compatibility

Windows updates change the hypervisor internals. The Intel pattern needed adjustment for recent builds. A more robust pattern matching system would improve reliability.

### Low Level Dumb Stuff

The major set backs were not anything specific but just a simple mistake which propagated itself heavily, working on being a better programmer or sticking to a more robust style would probably help in a lot of these cases.

---

## Results

The driver successfully:
- ✅ Hooks UEFI boot services to detect `winload.efi`
- ✅ Patches memory allocation to extend hypervisor image
- ✅ Injects position-independent code into the hypervisor
- ✅ Intercepts VM exit events with custom handler
- ✅ Provides working hypercall interface via CPUID
- ✅ Supports both Intel VT-x

---

## Ethical Considerations

This project demonstrates techniques that could be misused. Important points:

⚠️ **This is research code** - not production-ready  
⚠️ **Educational purpose only** - understand the risks  
⚠️ **May violate warranties** - use on test systems only  
⚠️ **Security implications** - this bypasses OS protections  
⚠️ **Legal considerations** - check local laws and terms of service  

The project is released under the Unlicense (public domain) with explicit warranty disclaimers. Use responsibly and ethically.

---

## Future Improvements

Ideas for extending this research:

1. **Dynamic Payload Loading** - Load payload from file instead of embedding
2. **Robust Pattern Matching** - Version-agnostic signature detection  
3. **Extended Hypercall Interface** - More complex communication channel
4. **Multi-processor Support** - Handle all CPU cores properly
5. **Debugging Tools** - Better introspection of hypervisor state
6. **Security Research** - Study hypervisor vulnerabilities

---

## Source Code

The complete source code is available on GitHub:

**[ZczxyPkg/Driver-ExtendedHv](https://github.com/0xzczxy/ZczxyPkg)**

The repository includes:
- Full UEFI driver source
- Position-independent payload code
- Build scripts and tooling
- Documentation and comments

---

## References & Inspiration

This project builds on research from:
- [noahware/hyper-reV](https://github.com/noahware/hyper-reV/tree/main)
- [backengineering/Voyager](https://github.com/backengineering/Voyager/tree/master)
- [SamuelTulach/SecureHack](https://github.com/SamuelTulach/SecureHack)

---

## Conclusion

Building ExtendedHv taught me an incredible amount about low-level Windows internals, UEFI firmware development, and hypervisor architectures. The intersection of these technologies is fascinating—from the moment firmware hands off control to understanding how virtual machines are managed at the lowest level.

While this is a proof-of-concept, it demonstrates real techniques used in both security research and malware development. Understanding these mechanisms is crucial for defending against them.

---

**Daniel (0xzczxy)**  
*17 | Aspiring Security Researcher | UK*

[GitHub](https://github.com/0xzczxy) | [Home](/)
