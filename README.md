# extract-discord-tokens
## extract discord tokens from discord client/browser level db files or from discord client windows by memory scanning and regex!

this works for the latest discord client 2026 and uses 3 phase token extraction, the first phase is the traditional regex token extraction which on some machines no longer works and the 2nd phase is the fast memory scans,a full memory dump of discord proved that discord uses dynamic memory which changes every launch and this makes the memory offsets very unreliable but i did fine a stable authorization headers hex in memory dump observations and it never changes no matter how many times discord is restarted so that reduces the full memory scan which takes so much time and the third and final phase is full memory scan of the discord render processes which contain the authorization tokens and the last one is used as a fallback if discord updated the client and changed the observed memory hex that are stable so take into acount that updates wont break the functionality but they will increase memory scanning times which takes ~2 mins for a full memory scan on my end.The c++ script [main.cpp](https://github.com/ghostneverdies/extract-discord-tokens/edit/main/main.cpp) here prints found accounts in console
More Details Are Below On What I Found

## BUILD FROM SOURCE
Step 1:Clone the repo

```
git clone https://github.com/ghostneverdies/extract-discord-tokens.git
```
Step 2:Navigate To The Repo
```
cd extract-discord-tokens
```
Step 3:Build
```
.\build.bat
```

NOTE THAT YOU SHOULD HAVE MSVC BUILD TOOLS INSTALLED TO BUILD FROM SOURCE OTHERWISE NOTHING WILL HAPPEN

## DISCORD TOKEN MEMORY FORENSICS - OBSERVED DETAILS (validated across Several Discord launches)

WHO HOLDS TOKENS (Chromium process model):
- Renderer processes (--type=renderer): V8 JS heap, token read from localStorage by web-app JS
- Main/browser process: LevelDB cache + IPC mirror of auth headers
- GPU (--type=gpu-process), utility (--type=utility), crashpad (--type=crashpad): NEVER hold tokens
- NET: only main + renderer are token-bearing

COMMAND-LINE / PEB WALK (to classify processes):
- OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION)
- NtQueryInformationProcess(h, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), NULL)
- ProcessParameters = pbi.PebBaseAddress + 0x20 (x64) / 0x10 (x86)
- CommandLine UNICODE_STRING at ProcessParameters + 0x70 (x64) / 0x40 (x86)
- Keep if cl has --type=renderer OR lacks --type=; drop gpu/utility/crashpad; on read failure KEEP (safe)

ENCODING:
- All observed hits UTF-8; ZERO UTF-16 hits across both launches

STORAGE CONTAINERS (stable byte patterns; absolute addresses shift every launch):
1) HTTP HEADER CACHE (network stack) - holds "Authorization" header VALUE
   - Pre-fields vary per request (10/15/20/08/50 ...), so NOT stable
   - ONLY the ASCII name is stable:
     [..8-byte fields ..]  'A''u''t''h''o''r''i''z''a''t''i''o''n'  [..8-byte fields..]  <token>
   - Observed sample prefix (launch 1):
     22 00 00 00 18 00 00 00 10 00 00 00 08 00 00 00 50 00 00 00 48 00 00 00 "Authorization" ...
2) V8 / LevelDB RECORD - "token" key
   - Stable tail: 6D 00 00 00 05 74 6F 6B 65 6E 6D 00 00 00 03  <token>
                 (6D 00 00 00 05) 't''o''k''e''n' (6D 00 00 00 03)
   - i.e. varint-ish 6D length prefix 05, literal "token", then 6D prefix 03

ANCHOR BYTES (used for fast scan):
- Authorization: "Authorization" (13 ASCII bytes)
- V8 key:       6D 00 00 00 05 74 6F 6B 65 6E 6D 00 00 00 03

REGION / WALK RULES:
- MEM_COMMIT, readable protect (RO/RW/EXEC_R/EXEC_RW/EXEC_RW/PAGE_WRITECOPY 0x08)
- SKIP Type & MEM_IMAGE (0x1000000) regions - tokens never in image regions
- RegionSize cap 256MB (C#) / 50MB (C++ version), chunk/carry 1MB
- Fast pass: only decode/regex buffers containing an anchor (window ~768B after anchor, UTF-8)

DECOYS:
- Full heap sweep returned 3 JWT-like tokens; only 1 real. Other 2 are planted decoys
  scattered in heap to poison naive grabbers. Live Authorization-header anchor filters them.
  NOTE:THE DECOYS THEORY IS STILL NOT CONFIRMED FULLY

PERFORMANCE: full regex sweep ~120s -> filtered (main+renderer, MEM_IMAGE skip) ~89s
      -> anchored fast pass ~4.3s (28x). Fast first, full sweep ONLY as fallback
      (Discord updates may change auth header framing).
## Consider Giving This Repo A Star If You Found THis Helpful 🌟

# NOTE:THIS IS A POC AND IS NOT MEANT TO BE USED MALICIOUSLY AND IS PROVIDED TO YOU AS IS AND IS FOR EDUCATIONAL AND FORENSIC RESEARCH PURPOSES ONLY!THE AUTHOR IS NOT RESPONSIBLE FOR ANY DAMAGE CAUSED BY THIS TOOL AS THIS TOOL IS NOT INTENDED FOR ANY MALICIOUS PURPOSES.YOU SHOULD FOLLOW THE LAWS CORRECTLY.
