// main.cpp - Windows GUI client (Dear ImGui + Win32 + DirectX 11).
//
//   UI: file picker / upload button / realtime progress bars / result
//   download button. The transfer runs on a dedicated WORKER THREAD, so the
//   UI thread never blocks ("no freeze / not-responding" requirement).
//
// STRICT RULE COMPLIANT: first-party state uses STL and RAII; the
// worker thread + RAII sockets come from client/core/transfer.hpp.
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>
#include <commdlg.h>
#include <shellapi.h>

#include "../core/transfer.hpp"

#include <array>
#include <atomic>
#include <cstdio>
#include <filesystem>
#include <string>
#include <thread>

// ---------------------------------------------------------------------------
// D3D11 boilerplate (from the official Dear ImGui example)
// ---------------------------------------------------------------------------
static ID3D11Device*           g_pd3dDevice = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*         g_pSwapChain = nullptr;
static bool                    g_SwapChainOccluded = false;
static UINT                    g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------
namespace {

std::string narrow(const wchar_t* w)
{
    if (w == nullptr || w[0] == L'\0') return {};
    const int need = ::WideCharToMultiByte(CP_UTF8, 0, w, -1,
                                           nullptr, 0, nullptr, nullptr);
    if (need <= 1) return {};
    std::string s(static_cast<std::size_t>(need - 1), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), need, nullptr, nullptr);
    return s;
}

struct AppState {
    std::array<char, 128> host{};
    int port = static_cast<int>(lgx::kDefaultPort);

    std::filesystem::path log_file;
    std::filesystem::path temp_result;
    std::filesystem::path ca_file = "certs/ca.crt";
    std::filesystem::path client_cert = "certs/client.crt";
    std::filesystem::path client_key = "certs/client.key";
    std::array<char, 128> server_name{};

    lgx::Progress     prog;
    std::atomic<bool> cancel{false};
    std::thread       worker;
    std::string       last_saved;

    AppState()
    {
        std::snprintf(host.data(), host.size(), "127.0.0.1");
        std::snprintf(server_name.data(), server_name.size(), "localhost");
        std::array<wchar_t, 32768> local_app_data{};
        const DWORD count = ::GetEnvironmentVariableW(
            L"LOCALAPPDATA", local_app_data.data(),
            static_cast<DWORD>(local_app_data.size()));
        std::error_code ec;
        std::filesystem::path state_dir = count > 0 && count < local_app_data.size()
            ? std::filesystem::path(local_app_data.data()) / "LGXLogTransfer"
            : std::filesystem::temp_directory_path(ec) / "LGXLogTransfer";
        std::filesystem::create_directories(state_dir, ec);
        if (ec) state_dir = ".";
        // Stable across GUI restarts so an interrupted upload finds its sidecar.
        temp_result = state_dir / "result.csv";
    }
    ~AppState() { stop_worker(); }

    bool busy() const
    {
        const lgx::Stage st = prog.get_stage();
        return st != lgx::Stage::Idle && st != lgx::Stage::Done &&
               st != lgx::Stage::Failed && st != lgx::Stage::Cancelled;
    }

    void stop_worker()
    {
        cancel.store(true);
        if (worker.joinable()) worker.join();
        cancel.store(false);
    }

    void start_transfer()
    {
        stop_worker(); // join any finished previous run
        prog.reset();
        const std::string h = host.data();
        const std::uint16_t p = static_cast<std::uint16_t>(port);
        const std::filesystem::path in = log_file;
        const std::filesystem::path out = temp_result;
        const std::filesystem::path ca = ca_file;
        const std::filesystem::path cert = client_cert;
        const std::filesystem::path key = client_key;
        const std::string expected = server_name.data();
        worker = std::thread([this, h, p, in, out, ca, cert, key, expected] {
            lgx::run_transfer(h, p, in, out, prog, cancel,
                              ca, expected, cert, key);
        });
    }
};

void pick_log_file(HWND owner, AppState& app)
{
    wchar_t buf[MAX_PATH] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = L"Log files (*.log;*.txt)\0*.log;*.txt\0All files\0*.*\0";
    ofn.lpstrFile = buf;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (::GetOpenFileNameW(&ofn) == TRUE)
        app.log_file = std::filesystem::path(buf);
}

void pick_certificate_file(HWND owner, std::filesystem::path& destination,
                           const wchar_t* title)
{
    wchar_t buf[MAX_PATH] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrTitle = title;
    ofn.lpstrFilter = L"Certificate/key files\0*.crt;*.pem;*.key\0All files\0*.*\0";
    ofn.lpstrFile = buf;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (::GetOpenFileNameW(&ofn) == TRUE)
        destination = std::filesystem::path(buf);
}

void save_result_as(HWND owner, AppState& app)
{
    wchar_t buf[MAX_PATH] = L"result.csv";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = L"CSV files (*.csv)\0*.csv\0All files\0*.*\0";
    ofn.lpstrFile = buf;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
    if (::GetSaveFileNameW(&ofn) == TRUE) {
        std::error_code ec;
        std::filesystem::copy_file(
            app.temp_result, std::filesystem::path(buf),
            std::filesystem::copy_options::overwrite_existing, ec);
        app.last_saved = ec ? std::string("save failed: ") + ec.message()
                            : std::string("saved: ") + narrow(buf);
    }
}

const char* stage_label(lgx::Stage s)
{
    switch (s) {
    case lgx::Stage::Idle:          return "Idle";
    case lgx::Stage::Hashing:       return "Computing source SHA-256...";
    case lgx::Stage::Connecting:    return "Connecting...";
    case lgx::Stage::TlsHandshake:  return "TLS 1.3 mutual authentication...";
    case lgx::Stage::Negotiating:   return "Negotiating resume offset...";
    case lgx::Stage::Uploading:     return "Uploading encrypted log stream...";
    case lgx::Stage::WaitingResult: return "Server is analyzing (parsing 500MB stream)...";
    case lgx::Stage::Downloading:   return "Downloading result.csv...";
    case lgx::Stage::Done:          return "Done - analysis result received";
    case lgx::Stage::Failed:        return "Failed";
    case lgx::Stage::Cancelled:     return "Cancelled";
    }
    return "?";
}

void draw_app_window(HWND hwnd, AppState& app)
{
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("Log Transfer Client", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                 ImGuiWindowFlags_NoSavedSettings);

    ImGui::TextUnformatted("Large Log Analysis & Transfer Client");
    ImGui::Separator();
    ImGui::Spacing();

    const bool busy = app.busy();

    // --- server address ---------------------------------------------------
    ImGui::BeginDisabled(busy);
    ImGui::SetNextItemWidth(220);
    ImGui::InputText("Server IP / host", app.host.data(), app.host.size());
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120);
    ImGui::InputInt("Port", &app.port);
    if (app.port < 1) app.port = 1;
    if (app.port > 65535) app.port = 65535;
    ImGui::SetNextItemWidth(220);
    ImGui::InputText("TLS server name", app.server_name.data(),
                     app.server_name.size());
    if (ImGui::Button("CA..."))
        pick_certificate_file(hwnd, app.ca_file, L"Select server CA certificate");
    ImGui::SameLine(); ImGui::TextDisabled("%s", app.ca_file.string().c_str());
    if (ImGui::Button("Client cert..."))
        pick_certificate_file(hwnd, app.client_cert, L"Select client certificate");
    ImGui::SameLine(); ImGui::TextDisabled("%s", app.client_cert.string().c_str());
    if (ImGui::Button("Client key..."))
        pick_certificate_file(hwnd, app.client_key, L"Select client private key");
    ImGui::SameLine(); ImGui::TextDisabled("%s", app.client_key.string().c_str());

    // --- file picker --------------------------------------------------------
    ImGui::Spacing();
    if (ImGui::Button("Select Log File...", ImVec2(180, 0)))
        pick_log_file(hwnd, app);
    ImGui::SameLine();
    if (app.log_file.empty()) {
        ImGui::TextDisabled("(no file selected)");
    } else {
        std::error_code ec;
        const auto sz = std::filesystem::file_size(app.log_file, ec);
        ImGui::Text("%s  (%.1f MB)", app.log_file.string().c_str(),
                    ec ? 0.0 : static_cast<double>(sz) / (1024.0 * 1024.0));
    }
    ImGui::EndDisabled();

    // --- upload -------------------------------------------------------------
    ImGui::Spacing();
    ImGui::BeginDisabled(busy || app.log_file.empty() ||
                         app.server_name[0] == '\0' || app.ca_file.empty() ||
                         app.client_cert.empty() || app.client_key.empty());
    if (ImGui::Button("Upload & Analyze", ImVec2(180, 36)))
        app.start_transfer();
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!busy);
    if (ImGui::Button("Cancel", ImVec2(100, 36)))
        app.cancel.store(true);
    ImGui::EndDisabled();

    // --- progress -------------------------------------------------------------
    ImGui::Spacing();
    ImGui::Separator();
    const lgx::Stage st = app.prog.get_stage();
    ImGui::Text("Status: %s", stage_label(st));

    const std::uint64_t hashed = app.prog.hashed.load();
    const std::uint64_t htotal = app.prog.hash_total.load();
    const float hash_fraction = htotal ? static_cast<float>(
        static_cast<double>(hashed) / static_cast<double>(htotal)) : 0.0f;
    char hash_overlay[96];
    std::snprintf(hash_overlay, sizeof(hash_overlay), "SHA-256 %.1f%%",
                  hash_fraction * 100.0f);
    ImGui::ProgressBar(hash_fraction, ImVec2(-1, 0), hash_overlay);

    const std::uint64_t sent = app.prog.sent.load();
    const std::uint64_t stot = app.prog.send_total.load();
    const float upf = stot ? static_cast<float>(
        static_cast<double>(sent) / static_cast<double>(stot)) : 0.0f;
    char overlay[96];
    std::snprintf(overlay, sizeof(overlay),
                  "Upload %.1f%% (resumed %.1f MB, %.1f / %.1f MB)",
                  upf * 100.0f,
                  static_cast<double>(app.prog.resumed_offset.load()) /
                      (1024.0 * 1024.0),
                  static_cast<double>(sent) / (1024.0 * 1024.0),
                  static_cast<double>(stot) / (1024.0 * 1024.0));
    ImGui::ProgressBar(upf, ImVec2(-1, 0), overlay);

    const std::uint64_t rcv  = app.prog.received.load();
    const std::uint64_t rtot = app.prog.recv_total.load();
    const float dnf = rtot ? static_cast<float>(
        static_cast<double>(rcv) / static_cast<double>(rtot)) : 0.0f;
    std::snprintf(overlay, sizeof(overlay), "Download %.1f%%  (%llu / %llu B)",
                  dnf * 100.0f, (unsigned long long)rcv,
                  (unsigned long long)rtot);
    ImGui::ProgressBar(dnf, ImVec2(-1, 0), overlay);

    // --- result / error -----------------------------------------------------
    ImGui::Spacing();
    if (st == lgx::Stage::Failed || st == lgx::Stage::Cancelled) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.4f, 0.4f, 1.0f));
        ImGui::TextWrapped("Error: %s", app.prog.error().c_str());
        ImGui::PopStyleColor();
    }
    if (st == lgx::Stage::Done) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 1.0f, 0.5f, 1.0f));
        ImGui::TextWrapped("result.csv received (%llu bytes).",
                           (unsigned long long)rtot);
        ImGui::PopStyleColor();
        if (ImGui::Button("Download Result (Save As...)", ImVec2(260, 30)))
            save_result_as(hwnd, app);
        ImGui::SameLine();
        if (ImGui::Button("Open in default app", ImVec2(180, 30)))
            ::ShellExecuteW(nullptr, L"open",
                            app.temp_result.wstring().c_str(),
                            nullptr, nullptr, SW_SHOWNORMAL);
        if (!app.last_saved.empty())
            ImGui::TextDisabled("%s", app.last_saved.c_str());
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextDisabled("Transfer runs on a worker thread - UI stays responsive.");
    ImGui::End();
}

} // namespace

// ---------------------------------------------------------------------------
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    ImGui_ImplWin32_EnableDpiAwareness();
    const float main_scale = ImGui_ImplWin32_GetDpiScaleForMonitor(
        ::MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY));

    WNDCLASSEXW wc = {sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L,
                      GetModuleHandle(nullptr), nullptr, nullptr, nullptr,
                      nullptr, L"LogTransferClient", nullptr};
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(
        wc.lpszClassName, L"Log Transfer Client (C++ / Dear ImGui)",
        WS_OVERLAPPEDWINDOW, 100, 100,
        static_cast<int>(820 * main_scale), static_cast<int>(700 * main_scale),
        nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr; // no imgui.ini clutter
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.ScaleAllSizes(main_scale);
    style.FontScaleDpi = main_scale;

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    {
        AppState app; // scoped so the worker thread is joined before teardown

        bool done = false;
        while (!done) {
            MSG msg;
            while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
                ::TranslateMessage(&msg);
                ::DispatchMessage(&msg);
                if (msg.message == WM_QUIT) done = true;
            }
            if (done) break;

            if (g_SwapChainOccluded &&
                g_pSwapChain->Present(0, DXGI_PRESENT_TEST) ==
                    DXGI_STATUS_OCCLUDED) {
                ::Sleep(10);
                continue;
            }
            g_SwapChainOccluded = false;

            if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
                CleanupRenderTarget();
                g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight,
                                            DXGI_FORMAT_UNKNOWN, 0);
                g_ResizeWidth = g_ResizeHeight = 0;
                CreateRenderTarget();
            }

            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            draw_app_window(hwnd, app);

            ImGui::Render();
            const float clear[4] = {0.10f, 0.11f, 0.12f, 1.00f};
            g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView,
                                                    nullptr);
            g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView,
                                                       clear);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

            const HRESULT hr = g_pSwapChain->Present(1, 0);
            g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);
        }
    } // AppState dtor: cancel + join worker (clean resource return)

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

// ---------------------------------------------------------------------------
// D3D helpers (verbatim from the official Dear ImGui example)
// ---------------------------------------------------------------------------
bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = {D3D_FEATURE_LEVEL_11_0,
                                                    D3D_FEATURE_LEVEL_10_0};
    HRESULT res = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
        featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
        &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED)
        res = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags,
            featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
            &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK) return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_ID3D11Texture2D,
                            reinterpret_cast<void**>(&pBackBuffer));
    if (pBackBuffer != nullptr) {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr,
                                             &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) {
        g_mainRenderTargetView->Release();
        g_mainRenderTargetView = nullptr;
    }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;

    switch (msg) {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED) return 0;
        g_ResizeWidth = (UINT)LOWORD(lParam);
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0; // no ALT menu
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
