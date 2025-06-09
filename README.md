# ETW Autologger Analyzer

A Go-based tool for analyzing Windows Event Tracing (ETW) autologger configurations and their associated providers. This tool reads autologger settings from the Windows registry and displays comprehensive information about ETW providers, their configurations, and event filtering settings.

## Features

- **List Autologgers**: Discover all available ETW autologgers on the system
- **Analyze Configuration**: Display detailed autologger configuration including buffer settings, file modes, and status
- **Provider Analysis**: Show all ETW providers associated with an autologger
- **Event Filtering**: Extract and display filtered event IDs for each provider
- **Provider Name Resolution**: Resolve provider GUIDs to human-readable names when available

## Installation

### Prerequisites

- Go 1.19 or later
- Windows operating system (required for registry access)
- Administrator privileges (recommended for full registry access)

## Usage

### List All Available Autologgers

```powershell
go run main.go -list
```

This command displays all ETW autologgers configured on the system:

```
Available Autologgers (15 found):
==================================================
- AppModel
- Circular Kernel Context Logger
- DefenderApiLogger
- DefenderAuditLogger
- EventLog-Application
- ...
```

### Analyze Specific Autologger

```powershell
go run main.go -autologger <autologger-name>
```

Example:
```powershell
go run main.go -autologger DefenderApiLogger
```

This displays:

1. **Autologger Configuration Table**:
   - Registry values and their types
   - Buffer settings (size, minimum/maximum buffers)
   - File mode flags with descriptions
   - Start/stop status

2. **ETW Providers Summary Table**:
   - Provider GUIDs and resolved names
   - Enable/disable status
   - Event ID filters (if configured)

3. **Detailed Event IDs**:
   - Complete list of filtered event IDs per provider

### Command Line Options

| Option | Description | Required |
|--------|-------------|----------|
| `-list` | List all available autologgers | No |
| `-autologger <name>` | Analyze specific autologger by name | Yes (unless using -list) |

## Output Format

### Autologger Configuration

The tool displays autologger settings in a structured table format:

```
Autologger Configuration: DefenderApiLogger
============================================================
| Property             | Type            | Value                |
|----------------------|-----------------|----------------------|
| Age                  | REG_DWORD       | 0                    |
| BufferSize           | REG_DWORD       | 64                   |
| ClockType            | REG_DWORD       | 1                    |
| FlushTimer           | REG_DWORD       | 0                    |
| GUID                 | REG_SZ          | {guid}               |
| LogFileMode          | REG_DWORD       | 0x00000004           |
| MaximumBuffers       | REG_DWORD       | 64                   |
| MinimumBuffers       | REG_DWORD       | 16                   |
| Start                | REG_DWORD       | 1                    |
| Status               | REG_DWORD       | 0                    |
```

### ETW Providers

Providers are displayed with their associated metadata:

```
ETW Providers under DefenderApiLogger (5 found):

| GUID                                     | Provider Name                       | Enabled  | Event IDs            |
|------------------------------------------|-------------------------------------|----------|----------------------|
| {11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}  | Microsoft-Windows-WDAG-PolicyEval   | Yes      | [1, 2, 3, 4]        |
| {2a576b87-09a7-520e-c21a-4942f0271d67}  | Microsoft-Windows-Security-Mitig... | No       | No Filters          |
```

## Technical Details

### Registry Locations

The tool reads data from these Windows registry locations:

- **Autologger Base Path**: `SYSTEM\CurrentControlSet\Control\WMI\Autologger`
- **Provider Publishers**: `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers`
- **WMI Providers**: `SYSTEM\CurrentControlSet\Control\WMI`

### Event ID Parsing

The tool supports multiple event ID storage formats:

- **Binary Data**: 16-bit and 32-bit little-endian integers
- **DWORD Values**: Single event IDs stored as registry DWORD
- **Multiple Value Names**: Checks common registry value names (`EventId`, `Events`, `Id`)

### LogFileMode Flags

The tool decodes LogFileMode bitmasks into human-readable descriptions:

- `FILE_MODE_WRITE` (0x00000001)
- `FILE_MODE_CIRCULAR` (0x00000004)
- `FILE_MODE_REAL_TIME` (0x00000020)
- `FILE_MODE_BUFFERING` (0x00000200)
- And many more...

## Use Cases

### Security Analysis

- **Defender Analysis**: Examine Windows Defender's ETW logging configuration
- **Event Monitoring**: Understand which events are being captured
- **Provider Discovery**: Find active ETW providers and their settings

### System Administration

- **Performance Tuning**: Review buffer settings and logging modes
- **Troubleshooting**: Verify autologger configurations
- **Audit Compliance**: Document ETW logging settings

### Research and Development

- **ETW Development**: Understand existing provider configurations
- **Forensics**: Analyze system logging capabilities
- **Reverse Engineering**: Map ETW provider relationships

## Error Handling

The tool gracefully handles common scenarios:

- **Missing Autologgers**: Clear error messages for non-existent autologgers
- **Registry Access**: Handles permission issues and missing keys
- **Provider Resolution**: Falls back to GUID display when names cannot be resolved
- **Data Parsing**: Robust parsing of various registry data formats

## Dependencies

- `golang.org/x/sys/windows/registry`: Windows registry access
- Go standard library packages for binary parsing and string manipulation

## Limitations

- **Windows Only**: Requires Windows OS for registry access
- **Registry Permissions**: Some registry keys may require administrator privileges
- **Provider Names**: Not all provider GUIDs can be resolved to friendly names
- **Dynamic Changes**: Shows static configuration, not runtime state
