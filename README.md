# RapMusic R1 — one-click GitHub build

Target: SA-MP 0.3.7-R1, Windows 32-bit.

This package is set up so GitHub Actions builds `RapMusic.asi` with LLVM-MinGW. No Visual Studio installation is required on the local PC.

## Build
1. Create an empty GitHub repository.
2. Upload the contents of this folder.
3. Open the repository's **Actions** tab.
4. Run **Build RapMusic R1**.
5. When it finishes, open the workflow run and download the `RapMusic-R1` artifact.

The artifact contains `RapMusic.asi`.
