#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ws2_32.lib")

namespace {

using CMDPROC = void(__cdecl*)(const char*);
using AddCommandFn = void(__thiscall*)(uintptr_t, const char*, CMDPROC);
using AddMessageFn = void(__thiscall*)(uintptr_t, uint32_t, const char*);

constexpr DWORD R1_ENTRYPOINT = 0x31DF13;
constexpr uintptr_t R1_INPUT_PTR = 0x21A0E8;
constexpr uintptr_t R1_ADD_COMMAND = 0x65AD0;
constexpr uintptr_t R1_CHAT_PTR = 0x21A0E4;
constexpr uintptr_t R1_ADD_MESSAGE = 0x645A0;

constexpr char CLIENT_ID[] = "88fd5626440e4b7d9c7017a8ae17776c";
constexpr char REDIRECT_URI[] = "http://127.0.0.1:8888/callback";

constexpr char TOKEN_FILE[] = "RapMusic_token.txt";

HMODULE g_samp = nullptr;
uintptr_t g_base = 0;
volatile LONG g_registered = 0;

std::string g_accessToken;
std::string g_refreshToken;
DWORD g_expiresAt = 0;

uintptr_t base() {
    return reinterpret_cast<uintptr_t>(g_samp);
}

bool readable(const void* p, SIZE_T size) {
    if (!p || size == 0) return false;

    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(p, &mbi, sizeof(mbi)))
        return false;

    if (mbi.State != MEM_COMMIT)
        return false;

    const DWORD protect = mbi.Protect & 0xFF;
    if (protect == PAGE_NOACCESS || protect == PAGE_GUARD)
        return false;

    uintptr_t begin = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    uintptr_t end = begin + mbi.RegionSize;
    uintptr_t addr = reinterpret_cast<uintptr_t>(p);

    return addr >= begin && size <= (end - addr);
}

bool validModule() {
    if (!g_samp) return false;

    auto dos =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(g_samp);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    auto nt =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(g_base + dos->e_lfanew);

    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
        return false;

    return nt->OptionalHeader.AddressOfEntryPoint == R1_ENTRYPOINT;
}

void chat(const char* text) {
    auto slot =
        reinterpret_cast<uintptr_t*>(g_base + R1_CHAT_PTR);

    if (!readable(slot, sizeof(uintptr_t)))
        return;

    auto pChat = *slot;
    if (!pChat)
        return;

    auto fn =
        reinterpret_cast<AddMessageFn>(g_base + R1_ADD_MESSAGE);

    if (!readable(reinterpret_cast<const void*>(fn), 1))
        return;

    fn(pChat, 0xFFFFFFFFu, text);
}

std::string urlEncode(const std::string& s) {
    const char* hex = "0123456789ABCDEF";
    std::string out;

    for (unsigned char c : s) {
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += hex[(c >> 4) & 0xF];
            out += hex[c & 0xF];
        }
    }

    return out;
}

std::string base64url(const unsigned char* data, size_t len) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_";

    std::string out;
    int val = 0;
    int bits = -6;

    for (size_t i = 0; i < len; ++i) {
        val = (val << 8) | data[i];
        bits += 8;

        while (bits >= 0) {
            out.push_back(table[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }

    if (bits > -6)
        out.push_back(table[((val << 8) >> (bits + 8)) & 0x3F]);

    return out;
}

std::string sha256Base64Url(const std::string& input) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;

    DWORD hashObjectSize = 0;
    DWORD result = 0;

    if (BCryptOpenAlgorithmProvider(
            &alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return "";

    if (BCryptGetProperty(
            alg,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&hashObjectSize),
            sizeof(hashObjectSize),
            &result,
            0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return "";
    }

    std::vector<unsigned char> object(hashObjectSize);
    unsigned char digest[32]{};

    if (BCryptCreateHash(
            alg,
            &hash,
            object.data(),
            hashObjectSize,
            nullptr,
            0,
            0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return "";
    }

    BCryptHashData(
        hash,
        reinterpret_cast<PUCHAR>(
            const_cast<char*>(input.data())),
        static_cast<ULONG>(input.size()),
        0);

    BCryptFinishHash(hash, digest, sizeof(digest), 0);

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    return base64url(digest, sizeof(digest));
}

std::string randomString(size_t length) {
    static const char chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-._~";

    std::vector<unsigned char> bytes(length);

    if (BCryptGenRandom(
            nullptr,
            bytes.data(),
            static_cast<ULONG>(bytes.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return "";

    std::string out;
    out.reserve(length);

    for (unsigned char b : bytes)
        out += chars[b % (sizeof(chars) - 1)];

    return out;
}

std::string jsonValue(
    const std::string& json,
    const std::string& key) {

    std::string needle = "\"" + key + "\"";
    size_t p = json.find(needle);

    if (p == std::string::npos)
        return "";

    p = json.find(':', p);
    if (p == std::string::npos)
        return "";

    p++;

    while (p < json.size() &&
           (json[p] == ' ' || json[p] == '\t'))
        p++;

    if (p >= json.size() || json[p] != '"')
        return "";

    p++;

    std::string out;
    bool escape = false;

    for (; p < json.size(); ++p) {
        char c = json[p];

        if (escape) {
            if (c == 'n') out += '\n';
            else if (c == 'r') out += '\r';
            else if (c == 't') out += '\t';
            else out += c;

            escape = false;
            continue;
        }

        if (c == '\\') {
            escape = true;
            continue;
        }

        if (c == '"')
            break;

        out += c;
    }

    return out;
}

bool httpRequest(
    const wchar_t* method,
    const wchar_t* path,
    const std::string& body,
    const std::wstring& extraHeaders,
    std::string& response,
    DWORD& status) {

    response.clear();
    status = 0;

    HINTERNET session = WinHttpOpen(
        L"RapMusic/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!session)
        return false;

    HINTERNET connect = WinHttpConnect(
        session,
        L"api.spotify.com",
        INTERNET_DEFAULT_HTTPS_PORT,
        0);

    if (!connect) {
        WinHttpCloseHandle(session);
        return false;
    }

    HINTERNET request = WinHttpOpenRequest(
        connect,
        method,
        path,
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    std::wstring headers =
        L"Accept: application/json\r\n";

    if (!g_accessToken.empty()) {
        headers += L"Authorization: Bearer ";
        headers += std::wstring(
            g_accessToken.begin(),
            g_accessToken.end());
        headers += L"\r\n";
    }

    headers += extraHeaders;

    BOOL ok = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(-1L),
        body.empty()
            ? WINHTTP_NO_REQUEST_DATA
            : reinterpret_cast<LPVOID>(
                const_cast<char*>(body.data())),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0);

    if (!ok) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    ok = WinHttpReceiveResponse(
        request,
        nullptr);

    if (!ok) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD size = sizeof(status);

    WinHttpQueryInfo(
        request,
        WINHTTP_QUERY_STATUS_CODE |
        WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX.
        &status,
        &size,
        WINHTTP_NO_HEADER_INDERX);

    while (true) {
        DWORD available = 0;

        if (!WinHttpQueryDataAvailable(
                request,
                &available))
            break;

        if (!available)
            break;

        std::vector<char> buffer(available + 1);
        DWORD read = 0;

        if (!WinHttpReadData(
                request,
                buffer.data(),
                available,
                &read))
            break;

        response.append(buffer.data(), read);
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    return true;
}

bool saveTokens() {
    std::ofstream f(TOKEN_FILE, std::ios::trunc);

    if (!f)
        return false;

    f << g_accessToken << "\n";
    f << g_refreshToken << "\n";
    f << g_expiresAt << "\n";

    return true;
}

bool loadTokens() {
    std::ifstream f(TOKEN_FILE);

    if (!f)
        return false;

    std::getline(f, g_accessToken);
    std::getline(f, g_refreshToken);

    std::string expires;
    std::getline(f, expires);

    if (!expires.empty())
        g_expiresAt = static_cast<DWORD>(
            strtoul(expires.c_str(), nullptr, 10));

    return !g_accessToken.empty();
}

bool refreshToken() {
    if (g_refreshToken.empty())
        return false;

    std::string body =
        "grant_type=refresh_token&"
        "refresh_token=" +
        urlEncode(g_refreshToken) +
        "&client_id=" +
        urlEncode(CLIENT_ID);

    std::string response;
    DWORD status = 0;

    if (!httpRequest(
            L"POST",
            L"/api/token",
            body,
            L"Content-Type: application/x-www-form-urlencoded\r\n",
            response,
            status))
        return false;

    if (status != 200)
        return false;

    std::string access =
        jsonValue(response, "access_token");

    if (access.empty())
        return false;

    g_accessToken = access;

    std::string refresh =
        jsonValue(response, "refresh_token");

    if (!refresh.empty())
        g_refreshToken = refresh;

    std::string expires =
        jsonValue(response, "expires_in");

    DWORD seconds = expires.empty()
        ? 3600
        : static_cast<DWORD>(
            strtoul(expires.c_str(), nullptr, 10));

    g_expiresAt =
        GetTickCount() / 1000 + seconds;

    saveTokens();

    return true;
}

bool spotifyRequest(
    const wchar_t* method,
    const wchar_t* path,
    const std::string& body,
    std::string& response,
    DWORD& status) {

    if (g_accessToken.empty())
        loadTokens();

    DWORD now = GetTickCount() / 1000;

    if (g_accessToken.empty() ||
        (g_expiresAt && now + 60 >= g_expiresAt)) {

        if (!refreshToken())
            return false;
    }

    if (!httpRequest(
            method,
            path,
            body,
            L"",
            response,
            status))
        return false;

    if (status == 401) {
        if (!refreshToken())
            return false;

        response.clear();

        if (!httpRequest(
                method,
                path,
                body,
                L"",
                response,
                status))
            return false;
    }

    return true;
}

void authThread() {
    std::string verifier = randomString(64);
    std::string challenge = sha256Base64Url(verifier);
    std::string state = randomString(32);

    if (verifier.empty() ||
        challenge.empty() ||
        state.empty()) {
        chat("~ RapMusic: failed to generate PKCE data.");
        return;
    }

    std::string authUrl =
        "https://accounts.spotify.com/authorize?"
        "client_id=" + urlEncode(CLIENT_ID) +
        "&response_type=code"
        "&redirect_uri=" + urlEncode(REDIRECT_URI) +
        "&code_challenge_method=S256"
        "&code_challenge=" + urlEncode(challenge) +
        "&state=" + urlEncode(state) +
        "&scope=" +
        urlEncode(
            "user-modify-playback-state "
            "user-read-playback-state "
            "user-read-currently-playing");

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        chat("~ RapMusic: Winsock initialization failed.");
        return;
    }

    SOCKET server = socket(
        AF_INET,
        SOCK_STREAM,
        IPPROTO_TCP);

    if (server == INVALID_SOCKET) {
        WSACleanup();
        chat("~ RapMusic: callback server failed.");
        return;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8888);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (bind(
            server,
            reinterpret_cast<sockaddr*>(&addr),
            sizeof(addr)) == SOCKET_ERROR ||
        listen(server, 1) == SOCKET_ERROR) {

        closesocket(server);
        WSACleanup();

        chat("~ RapMusic: port 8888 unavailable.");
        return;
    }

    ShellExecuteA(
        nullptr,
        "open",
        authUrl.c_str(),
        nullptr,
        nullptr,
        SW_SHOWNORMAL);

    chat("~ RapMusic: Spotify login opened in browser.");

    char buffer[8192]{};

    SOCKET client = accept(
        server,
        nullptr,
        nullptr);

    if (client == INVALID_SOCKET) {
        closesocket(server);
        WSACleanup();
        return;
    }

    int received = recv(
        client,
        buffer,
        sizeof(buffer) - 1,
        0);

    std::string request;

    if (received > 0)
        request.assign(buffer, received);

    std::string responsePage =
        "<html><body>"
        "<h2>RapMusic authentication complete.</h2>"
        "<p>You can close this window.</p>"
        "</body></html>";

    std::string httpResponse =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: " +
        std::to_string(responsePage.size()) +
        "\r\nConnection: close\r\n\r\n" +
        responsePage;

    send(
        client,
        httpResponse.c_str(),
        static_cast<int>(httpResponse.size()),
        0);

    closesocket(client);
    closesocket(server);
    WSACleanup();

    size_t q = request.find("GET /callback?");

    if (q == std::string::npos) {
        chat("~ RapMusic: invalid Spotify callback.");
        return;
    }

    size_t start = q + 14;
    size_t end = request.find(' ', start);

    if (end == std::string::npos) {
        chat("~ RapMusic: invalid callback.");
        return;
    }

    std::string query =
        request.substr(start, end - start);

    auto getParam = [&](const char* name) -> std::string {
        std::string needle =
            std::string(name) + "=";

        size_t p = query.find(needle);

        if (p == std::string::npos)
            return "";

        p += needle.size();

        size_t e = query.find('&', p);

        if (e == std::string::npos)
            e = query.size();

        return query.substr(p, e - p);
    };

    std::string code = getParam("code");
    std::string returnedState = getParam("state");

    if (code.empty() ||
        returnedState != state) {

        chat("~ RapMusic: Spotify authorization failed.");
        return;
    }

    std::string body =
        "grant_type=authorization_code"
        "&code=" + urlEncode(code) +
        "&redirect_uri=" + urlEncode(REDIRECT_URI) +
        "&client_id=" + urlEncode(CLIENT_ID) +
        "&code_verifier=" + urlEncode(verifier);

    std::string tokenResponse;
    DWORD status = 0;

    if (!httpRequest(
            L"POST",
            L"/api/token",
            body,
            L"Content-Type: application/x-www-form-urlencoded\r\n",
            tokenResponse,
            status)) {

        chat("~ RapMusic: token request failed.");
        return;
    }

    if (status != 200) {
        chat("~ RapMusic: Spotify token rejected.");
        return;
    }

    g_accessToken =
        jsonValue(tokenResponse, "access_token");

    g_refreshToken =
        jsonValue(tokenResponse, "refresh_token");

    std::string expires =
        jsonValue(tokenResponse, "expires_in");

    DWORD seconds = expires.empty()
        ? 3600
        : static_cast<DWORD>(
            strtoul(expires.c_str(), nullptr, 10));

    g_expiresAt =
        GetTickCount() / 1000 + seconds;

    if (g_accessToken.empty()) {
        chat("~ RapMusic: no access token received.");
        return;
    }

    saveTokens();

    chat("~ RapMusic: Spotify connected successfully.");
}

DWORD WINAPI authThreadEntry(LPVOID) {
    authThread();
    return 0;
}

void startAuth() {
    HANDLE h = CreateThread(
        nullptr,
        0,
        authThreadEntry,
        nullptr,
        0,
        nullptr);

    if (h)
        CloseHandle(h);
}

void spotifyCommand(
    const char* command,
    const wchar_t* method,
    const wchar_t* path) {

    std::string response;
    DWORD status = 0;

    if (!spotifyRequest(
            method,
            path,
            "",
            response,
            status)) {
        chat("~ RapMusic: Spotify authentication required. Use /music auth.");
        return;
    }

    if (status == 204 || status == 200) {
        chat(command);
    } else {
        chat("~ RapMusic: Spotify API request failed.");
    }
}

void cmdMusic(const char* args) {
    if (!args)
        args = "";

    while (*args == ' ' || *args == '\t')
        ++args;

    if (_strnicmp(args, "auth", 4) == 0) {
        startAuth();
        return;
    }

    if (_strnicmp(args, "play", 4) == 0) {
        spotifyCommand(
            "~ RapMusic: playback resumed.",
            L"PUT",
            L"/v1/me/player/play");
        return;
    }

    if (_strnicmp(args, "pause", 5) == 0) {
        spotifyCommand(
            "~ RapMusic: playback paused.",
            L"PUT",
            L"/v1/me/player/pause");
        return;
    }

    if (_strnicmp(args, "next", 4) == 0) {
        spotifyCommand(
            "~ RapMusic: next track.",
            L"POST",
            L"/v1/me/player/next");
        return;
    }

    if (_strnicmp(args, "prev", 4) == 0) {
        spotifyCommand(
            "~ RapMusic: previous track.",
            L"POST",
            L"/v1/me/player/previous");
        return;
    }

    if (_strnicmp(args, "now", 3) == 0) {
        std::string response;
        DWORD status = 0;

        if (!spotifyRequest(
                L"GET",
                L"/v1/me/player/currently-playing",
                "",
                response,
                status)) {
            chat("~ RapMusic: Spotify authentication required.");
            return;
        }

        if (status != 200) {
            chat("~ RapMusic: nothing is currently playing.");
            return;
        }

        std::string track =
            jsonValue(response, "name");

        if (track.empty())
            track = "Unknown";

        std::string message =
            "~ RapMusic: Now playing - " + track;

        chat(message.c_str());
        return;
    }

    chat("~ RapMusic: usage: /music auth | play | pause | next | prev | now");
}

bool tryRegister() {
    auto inputSlot =
        reinterpret_cast<uintptr_t*>(
            g_base + R1_INPUT_PTR);

    if (!readable(
            inputSlot,
            sizeof(uintptr_t)))
        return false;

    auto input = *inputSlot;

    if (!input)
        return false;

    auto add =
        reinterpret_cast<AddCommandFn>(
            g_base + R1_ADD_COMMAND);

    if (!readable(
            reinterpret_cast<const void*>(add),
            1))
        return false;

    add(input, "music", cmdMusic);

    InterlockedExchange(
        &g_registered,
        1);

    chat("~ RapMusic R1 loaded. /music is registered.");

    return true;
}

DWORD WINAPI initThread(LPVOID) {
    for (int i = 0; i < 300; ++i) {
        g_samp = GetModuleHandleA("samp.dll");

        if (g_samp)
            break;

        Sleep(100);
    }

    if (!g_samp)
        return 0;

    g_base = base();

    if (!validModule())
        return 0;

    loadTokens();

    for (int i = 0;
         i < 300 && !g_registered;
         ++i) {

        if (tryRegister())
            break;

        Sleep(100);
    }

    return 0;
}

}

BOOL WINAPI DllMain(
    HINSTANCE h,
    DWORD reason,
    LPVOID) {

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);

        HANDLE thread =
            CreateThread(
                nullptr,
                0,
                initThread,
                nullptr,
                0,
                nullptr);

        if (thread)
            CloseHandle(thread);
    }

    return TRUE;
}
