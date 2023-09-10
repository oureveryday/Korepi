# Crack Info

## PatchLauncher

Automacally write launch info in Baymax64.ini and Launches Baymax Patch.

## Crack.BPT

Baymax Patch Tools project file.

* Search: `E8 3F 02 FE FF 48 8B F0`
* Replace: `48 C7 C6 01 00 00 00 90`

---

* Breakpoint: `FF 15 7F 5F 12 00`
* r8: Launch Info (String format `C:\cheat<@/>8<@/>000000000000000000<@/>Crackkkk`)
* r9,r13,r14: Launch Info String Length

---

## Launch Info

* `<@/>` : Info Separator

1. `C:\cheat`: Cheat Base Path (Config save location)
2. `8`: Role (`1`: `Fans`,`2`: `Verified`,`4`: `Translator`, `8`: `Sponsor`)
3. `000000000000000000`: Discord ID
4. `Crackkkk`: HWID
