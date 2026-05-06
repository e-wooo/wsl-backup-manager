# WSL Backup Manager v4.01

Language: [English](#english) | [中文](#%E4%B8%AD%E6%96%87)

## English

WSL Backup Manager v4.01 is a single-file Windows PowerShell tool for WSL2 backup and restore. It runs on Windows and calls Windows-side tools such as PowerShell, `wsl.exe`, WSL UNC paths, and 7-Zip. It is not a Linux/WSL shell script.

### Key Features

- FULL WSL distro backup.
- FULL clone restore to a new WSL instance.
- FULL overwrite restore with strong warnings and confirmation.
- USER home backup.
- CUSTOM directory backup.
- USER/CUSTOM restore.
- Backup list and batch delete.
- Diagnostics / environment self-check.
- DryRun mode for previewing high-risk operations.
- Manifest, SHA256, and OperationId audit data.
- Protected delete and guarded WSL operations.

### Important Limitations

- USER/CUSTOM backups use WSL UNC paths with Windows 7-Zip and do not guarantee full Linux metadata fidelity, including permissions, owner/group, or symlinks.
- FULL overwrite restore is destructive and replaces the target distro.
- `wsl --shutdown` affects all running WSL2 distributions.
- DryRun does not execute WSL or 7-Zip operations, but it also does not prove the real operation will succeed.
- This script does not automatically write `.wslconfig`.

### Requirements

- Windows 10/11 with WSL2.
- PowerShell 5.1 or PowerShell 7+.
- 7-Zip installed.
- Enough disk space for temporary tar files and final archives.
- A non-critical test distro before trusting overwrite restore.

Config (`wsl-backup-config.json`), logs (`logs/`), and default backup/install directories (`Backups/`, `Instances/`) are auto-created on first run.

### Basic Usage

Run PowerShell from the project directory:

```powershell
.\wsl-backup-manager_v4.01.ps1
```

Preview high-risk operations with DryRun:

```powershell
.\wsl-backup-manager_v4.01.ps1 -DryRun
```

### Recommended Workflow

1. Run Diagnostics first.
2. Create a FULL backup.
3. Test FULL clone restore to a new instance.
4. Only then consider FULL overwrite restore.
5. Use USER/CUSTOM backups for convenient file-level backups, not as full Linux metadata-preserving backups.

### Safety Notes

- Do not test overwrite restore on your main distro.
- Keep backups outside the WSL install path.
- Do not store the install root and backup root inside each other.

## 中文

WSL Backup Manager v4.01 是一个单文件 Windows PowerShell 工具，用于 WSL2 发行版的备份与恢复。它运行在 Windows 侧，会调用 PowerShell、`wsl.exe`、WSL UNC 路径和 7-Zip。它不是运行在 Linux/WSL 内部的 shell 脚本。

### 主要功能

- FULL WSL 发行版备份。
- FULL 克隆恢复到新的 WSL 实例。
- FULL 覆盖恢复，并带有强警告和确认流程。
- USER 用户 home 目录备份。
- CUSTOM 自定义目录备份。
- USER/CUSTOM 恢复。
- 备份列表查看和批量删除。
- Diagnostics / 环境自检。
- DryRun 预览模式，用于预览高风险操作。
- Manifest、SHA256 和 OperationId 审计信息。
- 受保护删除和受保护的 WSL 操作。

### 重要限制

- USER/CUSTOM 备份通过 WSL UNC 路径配合 Windows 7-Zip 处理，不保证完整保留 Linux 元数据，包括权限、owner/group 或 symlink。
- FULL 覆盖恢复是破坏性操作，会替换目标发行版。
- `wsl --shutdown` 会影响所有正在运行的 WSL2 发行版。
- DryRun 不会执行真实 WSL 或 7-Zip 操作，但也不能证明真实操作一定会成功。
- 本脚本不会自动写入 `.wslconfig`。

### 运行要求

- Windows 10/11，并启用 WSL2。
- PowerShell 5.1 或 PowerShell 7+。
- 已安装 7-Zip。
- 有足够磁盘空间存放临时 tar 文件和最终归档。
- 在信任覆盖恢复前，先使用非关键测试发行版验证流程。

配置文件（`wsl-backup-config.json`）、日志目录（`logs/`）和默认的备份/安装目录（`Backups/`、`Instances/`）在首次运行时自动创建。

### 基本用法

在项目目录中打开 PowerShell：

```powershell
.\wsl-backup-manager_v4.01.ps1
```

使用 DryRun 预览高风险操作：

```powershell
.\wsl-backup-manager_v4.01.ps1 -DryRun
```

### 推荐使用流程

1. 先运行 Diagnostics。
2. 创建一个 FULL 备份。
3. 先测试 FULL 克隆恢复到新实例。
4. 之后再考虑 FULL 覆盖恢复。
5. USER/CUSTOM 更适合做方便的文件级备份，不应当视为完整保留 Linux 元数据的备份方式。

### 安全提醒

- 不要第一次就在主力发行版上测试覆盖恢复。
- 备份目录应放在 WSL 安装路径之外。
- 不要让安装根目录和备份根目录互相包含。
