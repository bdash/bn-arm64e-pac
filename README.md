# Remove explicit ptrauth checks before tail calls

This Binary Ninja plug-in detects and removes explicit pointer authentication checks,
aka ptrauth or PAC, against `lr` prior to tail calls in order to declutter the higher-level ILs.

## Supported Binary Ninja versions

Only recent versions of Binary Ninja 5.1-dev are supported.

## Installation

```
git clone https://github.com/bdash/bn-arm64e-pac.git
cd bn-arm64e-pac
cargo build --release
ln -sf $PWD/target/release/libbn_arm64e_pac.dylib ~/Library/Application\ Support/Binary\ Ninja/plugins/
```

## Configuration

Removal of pointer authentication checks before tail calls is enabled by default as in most contexts
they're not relevant to a user.

If you wish to be more selective in the removal of these checks you can disable them via the
`bdash.arm64e-pac` setting in Binary Ninja's settings. The removal can then be applied on a per-function
basis by enabling `Remove explicit arm64e PAC checks` from the `Function Analysis` context menu.

## Background

arm64e functions often perform a tail call using an instruction sequence like the following:

```
19c01be2c     ff2303d5   autibsp 
19c01be30     d0071eca   eor     x16, x30, x30, lsl #0x1
19c01be34     5000f0b6   tbz     x16, #0x3e, 0x19c01be3c

19c01be38     208e38d4   brk     #0xc471

19c01be3c     a1450014   b       0x19c02d4c0
```

This validation ends up in Binary Ninja's HLIL in an incomplete/broken form:

```
19c01be34        int64_t x30
19c01be34        
19c01be34        if (((x30 ^ x30 << 1) & 0x40000000) == 0)
19c02d4d4            return _objc_msgSend(x0_2, "instrument:", &cfstr_MLMediaLibrary) __tailcall
```

[llvm::AArch64PAuth::AuthCheckMethod](https://github.com/llvm/llvm-project/blob/0014b49482c0862c140149c650d653b4e41fa9b4/llvm/lib/Target/AArch64/AArch64PointerAuth.h#L44-L86)
has more information about these checks. This plug-in currently recognizes only the
`HighBitsNoTBI` method as that is what is used on Apple platforms.
