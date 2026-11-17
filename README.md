# Antigravity Switcher

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-blue?logo=windows)](https://github.com/huvny-de/antigravity-switcher)
[![Framework](https://img.shields.io/badge/.NET-10.0%20WPF-purple?logo=dotnet)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Polling](https://img.shields.io/badge/Background%20CPU-0%25%20(No%20Polling)-brightgreen)](#-architecture--security)

A lightweight, translucent modern desktop widget for Windows designed to seamlessly track quotas and switch between multiple Google accounts in **Google Antigravity 2.0** with a single click.

---

## 🌟 Key Features

- **🔄 1-Click Instant Session Switching**:
  - Switch between unlimited ($N$) Google accounts effortlessly without opening a browser or restarting your IDE.
  - Automatically syncs and backs up the active session's latest tokens before applying the target account.
  
- **📊 Real-time Quota Gauges**:
  - Live tracking of **Gemini Weekly Limit** and **Rolling 5-Hour Limit**.
  - Dynamic status indicators:
    - 🟢 Green (> 40% quota remaining)
    - 🟡 Amber (15% - 40% quota remaining)
    - 🔴 Red (< 15% quota remaining)

- **⏳ Reset Timeline Tracking**:
  - Displays the exact replenishment date and time for each saved account (e.g., `⏳ 5H reset: 03:44 (3h 12m) • Weekly reset: 07/10 (5d 20h)`).
  - Easily decide which account to use first to maximize productivity and quota cycles.

- **🎨 Anti-Confusion Visual Badging**:
  - Generates 2-character smart badges (e.g., `N0`, `NP`, `AH`) based on email formatting.
  - Curated color palettes (Cyan, Violet, Amber, Teal, Rose) ensure similar account names are immediately distinguishable.

- **🛡️ Zero Background Polling (0% CPU)**:
  - No background timers, no daemon threads, no endpoint spamming.
  - In-memory 15-minute caching mechanism queries Google endpoints only on explicit demand or window activation.

- **🔒 100% Policy-Compliant & Native**:
  - Pure native implementation; no proxy servers, no man-in-the-middle token interceptors, no unauthorized rotation.
  - Follows standard **RFC 8252 (OAuth 2.0 for Native Apps)** with official Google OAuth Client specifications.
  - Credentials stored securely in **Windows Credential Manager** (`Advapi32.dll`).

---

## 🚀 Quick Start (Pre-built Binary)

1. Go to the [Releases](https://github.com/huvny-de/antigravity-switcher/releases) page.
2. Download `AntigravitySwitcher-win-x64.zip`.
3. Extract the folder anywhere on your Windows PC.
4. Run `AntigravitySwitcher.exe`.
   *(No .NET runtime or SDK installation required — self-contained executable).*

> **Prerequisite**: Google Antigravity 2.0 must be installed and signed in to at least one account.

---

## 📖 How to Use

1. **Save Your First Account**:
   - Open Antigravity and sign in to your primary Google account.
   - Launch `Antigravity Switcher` and click **`➕ Lưu tài khoản`**. Your account will appear with the active badge `● ĐANG DÙNG`.

2. **Add Additional Accounts ($N$ accounts)**:
   - In Antigravity, sign out and sign in to your second Google account.
   - In `Antigravity Switcher`, click **`➕ Lưu tài khoản`**.
   - Repeat for as many accounts as you need.

3. **Switch Between Accounts**:
   - Simply click **`⇄ Đổi sang`** next to any saved account.
   - The core language server updates within 2 seconds.

---

## 🛠️ Building from Source

### Prerequisites
- [.NET 10.0 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (or later)
- Windows 10/11 x64

### Build & Publish
```powershell
# Clone the repository
git clone https://github.com/huvny-de/antigravity-switcher.git
cd antigravity-switcher

# Publish standalone single-file binary
dotnet publish app/app.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish
```

The compiled standalone executable and runtime assets will be generated in `./publish`.

---

## 🏛️ Architecture & Security

- **Credential Storage**: Uses Windows Native `Advapi32.dll` APIs (`CredReadW`, `CredWriteW`, `CredDeleteW`, `CredEnumerateW`) targeting `gemini:antigravity` and namespaced profiles `gemini:antigravity_profile_*`.
- **Quota Endpoint**: Queries `https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary` directly via authenticated bearer tokens.
- **Silent Refresh**: Expired tokens are refreshed against `https://oauth2.googleapis.com/token` using the standard OAuth 2.0 Refresh Token Grant flow.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
