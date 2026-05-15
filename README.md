# WSL Backup Manager v4.2

Windows PowerShell / WSL2 local backup and restore utility.

---

## Requirements

- Windows 10/11 with WSL2
- PowerShell 5.1+ or PowerShell 7+
- [7-Zip](https://7-zip.org/) (auto-detected or configured in Settings)

## Features

- Backup and restore whole WSL distros
- Backup and restore Linux paths inside WSL
- Restore from external `.7z` / `.tar` archives
- Compression Level (Fast / Balanced / Max) and Resource Usage (Low / Normal / High) — chosen independently per backup
- Paginated list / safe delete with confirmation phrases
- Settings, logs, distro switching

## Safety

- **Replacing a distro is destructive.** A Safety Net backup is created automatically before overwrite, stored under `Backups/.safety-net/`.
- Delete and restore operations require exact confirmation phrases (`DELETE`, `REPLACE <name>`, `INSTALL NEW <name>`, `RESTORE PATH TO ...`).
- Use `-DryRun` to preview any supported operation without side effects.
- The script does **not** auto-write `.wslconfig`.

## Usage

```powershell
.\wsl-backup-manager_v4.2.ps1            # interactive menu
.\wsl-backup-manager_v4.2.ps1 -DryRun    # preview mode
```

On first run, the script creates `Backups/`, `Instances/`, `logs/`, and `wsl-backup-config.json` beside itself.

---

## 环境要求

- Windows 10/11，已安装 WSL2
- PowerShell 5.1+ 或 PowerShell 7+
- [7-Zip](https://7-zip.org/)（自动检测，或在 Settings 中配置）

## 功能

- 备份和恢复整个 WSL 发行版
- 备份和恢复 WSL 内 Linux 路径
- 从外部 `.7z` / `.tar` 压缩包恢复
- Compression Level（Fast / Balanced / Max）和 Resource Usage（Low / Normal / High）独立选择，互不影响
- 分页浏览 / 安全删除，需确认短语
- Settings、Logs、切换发行版

## 安全

- **覆盖发行版是破坏性操作。** 覆盖前自动创建 Safety Net 备份，存放在 `Backups/.safety-net/`。
- 删除和恢复需要输入精确确认短语（`DELETE`、`REPLACE <名称>`、`INSTALL NEW <名称>`、`RESTORE PATH TO ...`）。
- 使用 `-DryRun` 可预览操作，不产生任何副作用。
- 脚本**不会**自动写入 `.wslconfig`。

## 使用

```powershell
.\wsl-backup-manager_v4.2.ps1            # 交互菜单
.\wsl-backup-manager_v4.2.ps1 -DryRun    # 预览模式
```

首次运行时，脚本会在同目录下创建 `Backups/`、`Instances/`、`logs/` 和 `wsl-backup-config.json`。
