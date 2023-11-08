# Setup

*Modify! These scripts are modified from Josh-XT's [Setup repo](https://github.com/Josh-XT/Setup), made to work on my setup!*

## Quickstart:

Open terminal and copy/paste the following:

```bash
sudo apt install -y git
git clone https://github.com/atypdev/Setup
```

## Ubuntu 22.04 Workstation Setup

```bash
./Setup/WorkstationSetup.sh
```

## Ubuntu Server Setup

```bash
./Setup/ServerSetup.sh
```

## Windows 10 Setup

I [modified](https://github.com/Josh-XT/Setup) this script to supplement new Windows installs, since I tend to find myself doing so often.

The `WinSetup.ps1` script downloads and installs packages from Chocolatey, then the script creates a scheduled task to ensure those packages are always installed and up to date daily.  Packages can be found on [Chocolatey's website](https://chocolatey.org).

The package list used by the script can be modified any time, it is located at `C:\ProgramData\Automation\packages.csv`.

Open PowerShell as Administrator and run the following:

```bash
git clone https://github.com/atypdev/Setup
cd Setup
Set-ExecutionPolicy Bypass
.\WinSetup.ps1
```

#### Debloat

I used a site called [privacy.sexy](https://privacy.sexy/) to generate a Windows 10 debloat script.

```bash
git clone https://github.com/atypdev/Setup
cd Setup
Set-ExecutionPolicy Bypass
.\WinDebloat.ps1
```

## My Setup

### Workstation Setup

My operating system for my Desktop is Windows 10. I use [Visual Studio Code](https://code.visualstudio.com/) as my IDE for all code editing.

| Item  | Desktop |
|-------------------|-------------------|
| **Model**             | Custom Built |
| **CPU**               | [Intel Core i5-9400F](https://www.intel.com/content/www/us/en/products/sku/134898/intel-core-i59400-processor-9m-cache-up-to-4-10-ghz/specifications.html) |
| **GPU**               | [NVIDIA GeForce GTX 1660 Ti 6GB](https://www.asus.com/us/motherboards-components/graphics-cards/tuf-gaming/tuf-rtx4090-o24g-gaming/) | 
| **RAM**               | [16GB DDR4-3600](https://www.gskill.com/product/165/377/1649665420/F5-5200J3636D32GX2-RS5W-F5-5200J3636D32GA2-RS5W) | 
| **Storage**           | 1TB M2 | 
| **Monitor**           | 2x LG Ultrawide |