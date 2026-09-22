"""Sysmon records shaped as Winlogbeat/NXLog forward them, one per supported event ID.

The values follow well-known attack techniques (hand-written, not copied from any dataset): an Office
document starting PowerShell, a beacon, credential theft from lsass.exe, a Run-key persistence entry.
"""

from __future__ import annotations

from typing import Any

HOST = "WS-FIN-07.corp.example"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
MIMIKATZ = r"C:\Users\jsmith\AppData\Local\Temp\m.exe"
LSASS = r"C:\Windows\System32\lsass.exe"
PS_GUID = "{8a3c1f2e-0b1d-66e7-1a02-000000001a00}"
SHA256 = "a" * 64
MD5 = "b" * 32


def record(
    event_id: int, data: dict[str, Any], *, record_id: int = 1000, time: str = "2026-09-15T10:13:54Z"
) -> dict[str, Any]:
    return {
        "EventID": event_id,
        "TimeCreated": time,
        "Computer": HOST,
        "EventRecordID": record_id + event_id,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventData": data,
    }


PROCESS_CREATE = record(
    1,
    {
        "RuleName": "-",
        "UtcTime": "2026-09-15 10:13:54.120",
        "ProcessGuid": PS_GUID,
        "ProcessId": "6732",
        "Image": POWERSHELL,
        "FileVersion": "10.0.19041.3996 (WinBuild.160101.0800)",
        "Description": "Windows PowerShell",
        "Product": "Microsoft® Windows® Operating System",
        "Company": "Microsoft Corporation",
        "OriginalFileName": "PowerShell.EXE",
        "CommandLine": "powershell.exe -nop -w hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "CurrentDirectory": "C:\\Users\\jsmith\\Documents\\",
        "User": "CORP\\jsmith",
        "LogonId": "0x3e7a21",
        "IntegrityLevel": "Medium",
        "Hashes": f"MD5={MD5},SHA256={SHA256.upper()},IMPHASH=F1D2E3C4B5A6978812345678ABCDEF01",
        "ParentProcessGuid": "{8a3c1f2e-0b1a-66e7-1802-000000001a00}",
        "ParentProcessId": "5120",
        "ParentImage": WINWORD,
        "ParentCommandLine": '"WINWORD.EXE" /n "C:\\Users\\jsmith\\Downloads\\invoice.docm"',
        "ParentUser": "CORP\\jsmith",
    },
)

NETWORK = record(
    3,
    {
        "ProcessGuid": PS_GUID,
        "ProcessId": "6732",
        "Image": POWERSHELL,
        "User": "CORP\\jsmith",
        "Protocol": "tcp",
        "Initiated": "true",
        "SourceIsIpv6": "false",
        "SourceIp": "10.20.30.47",
        "SourceHostname": HOST,
        "SourcePort": "52114",
        "DestinationIsIpv6": "false",
        "DestinationIp": "192.0.2.66",
        "DestinationHostname": "-",
        "DestinationPort": "443",
    },
)

TERMINATE = record(5, {"ProcessGuid": PS_GUID, "ProcessId": "6732", "Image": POWERSHELL, "User": "CORP\\jsmith"})

IMAGE_LOAD = record(
    7,
    {
        "ProcessGuid": PS_GUID,
        "ProcessId": "6732",
        "Image": POWERSHELL,
        "ImageLoaded": r"C:\Windows\System32\vaultcli.dll",
        "FileVersion": "10.0.19041.1",
        "Description": "Credential Vault Client Library",
        "Product": "Microsoft® Windows® Operating System",
        "Company": "Microsoft Corporation",
        "OriginalFileName": "vaultcli.dll",
        "Hashes": f"SHA256={SHA256}",
        "Signed": "true",
        "Signature": "Microsoft Windows",
        "SignatureStatus": "Valid",
        "User": "CORP\\jsmith",
    },
)

REMOTE_THREAD = record(
    8,
    {
        "SourceProcessGuid": PS_GUID,
        "SourceProcessId": "6732",
        "SourceImage": POWERSHELL,
        "TargetProcessGuid": "{8a3c1f2e-0001-66e7-0c00-000000001a00}",
        "TargetProcessId": "3900",
        "TargetImage": r"C:\Windows\explorer.exe",
        "NewThreadId": "7788",
        "StartAddress": "0x00000245A1B20000",
        "StartModule": "-",
        "StartFunction": "-",
        "SourceUser": "CORP\\jsmith",
        "TargetUser": "CORP\\jsmith",
    },
)

LSASS_ACCESS = record(
    10,
    {
        "SourceProcessGUID": "{8a3c1f2e-0c3d-66e7-2b02-000000001a00}",
        "SourceProcessId": "7012",
        "SourceThreadId": "7016",
        "SourceImage": MIMIKATZ,
        "TargetProcessGUID": "{8a3c1f2e-0002-66e7-0c00-000000001a00}",
        "TargetProcessId": "712",
        "TargetImage": LSASS,
        "GrantedAccess": "0x1010",
        "CallTrace": r"C:\Windows\SYSTEM32\ntdll.dll+9d4c4|UNKNOWN(00007FF6A1B2C3D4)",
        "SourceUser": "CORP\\jsmith",
        "TargetUser": "NT AUTHORITY\\SYSTEM",
    },
)

FILE_CREATE = record(
    11,
    {
        "ProcessGuid": PS_GUID,
        "ProcessId": "6732",
        "Image": POWERSHELL,
        "TargetFilename": MIMIKATZ,
        "CreationUtcTime": "2026-09-15 10:14:02.001",
        "User": "CORP\\jsmith",
    },
)

REG_CREATE_KEY = record(
    12,
    {
        "EventType": "CreateKey",
        "ProcessGuid": PS_GUID,
        "ProcessId": "6732",
        "Image": POWERSHELL,
        "TargetObject": r"HKU\S-1-5-21-1-2-3-1104\Software\Classes\ms-settings\shell\open\command",
        "User": "CORP\\jsmith",
    },
)

REG_SET_RUN_KEY = record(
    13,
    {
        "EventType": "SetValue",
        "ProcessGuid": PS_GUID,
        "ProcessId": "6732",
        "Image": POWERSHELL,
        "TargetObject": r"HKU\S-1-5-21-1-2-3-1104\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        "Details": r"C:\Users\jsmith\AppData\Local\Temp\m.exe",
        "User": "CORP\\jsmith",
    },
)

REG_RENAME = record(
    14,
    {
        "EventType": "RenameKey",
        "ProcessGuid": PS_GUID,
        "ProcessId": "6732",
        "Image": POWERSHELL,
        "TargetObject": r"HKLM\SOFTWARE\Example\Old",
        "NewName": r"HKLM\SOFTWARE\Example\New",
        "User": "CORP\\jsmith",
    },
)

DNS = record(
    22,
    {
        "ProcessGuid": PS_GUID,
        "ProcessId": "6732",
        "QueryName": "update.bad.example",
        "QueryStatus": "0",
        "QueryResults": "type:  5 cdn.bad.example;::ffff:192.0.2.66;",
        "Image": POWERSHELL,
        "User": "CORP\\jsmith",
    },
)

FILE_DELETE = record(
    23,
    {
        "ProcessGuid": PS_GUID,
        "ProcessId": "6732",
        "Image": POWERSHELL,
        "TargetFilename": MIMIKATZ,
        "Hashes": f"SHA256={SHA256}",
        "IsExecutable": "true",
        "Archived": "false",
        "User": "CORP\\jsmith",
    },
)

ALL = (
    PROCESS_CREATE,
    NETWORK,
    TERMINATE,
    IMAGE_LOAD,
    REMOTE_THREAD,
    LSASS_ACCESS,
    FILE_CREATE,
    REG_CREATE_KEY,
    REG_SET_RUN_KEY,
    REG_RENAME,
    DNS,
    FILE_DELETE,
)
