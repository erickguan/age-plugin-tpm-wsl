# Read-only independent observation for a single disposable client namespace.
# -SoftwareOnly compiles and tests pure classifiers; it calls no native probe.
param(
    [Parameter(Mandatory=$true)][string]$Namespace,
    [switch]$SoftwareOnly
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Namespace -cnotmatch '\Aage-tpm-wsl-post-quantum-client-[0-9a-f]{32}\z') {
    throw 'Reserved lowercase client namespace required'
}
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace DisposableClientObservation {
    public sealed class Snapshot {
        public string sid;
        public bool root_absent;
        public bool key_absent;
    }

    public static class Probe {
        private static readonly IntPtr Invalid = new IntPtr(-1);
        private const int BadKeyset = unchecked((int)0x80090016);
        private const string Prefix = "age-tpm-wsl-post-quantum-client-";

        [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
        private static extern int NCryptOpenStorageProvider(out IntPtr provider, string name, int flags);
        [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)]
        private static extern int NCryptOpenKey(IntPtr provider, out IntPtr key, string name, int legacy, int flags);
        [DllImport("ncrypt.dll")]
        private static extern int NCryptFreeObject(IntPtr handle);
        [DllImport("shell32.dll")]
        private static extern int SHGetKnownFolderPath(ref Guid id, uint flags, IntPtr token, out IntPtr path);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern IntPtr FindFirstFileW(string path, out FindData data);
        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindClose(IntPtr search);

        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
        private struct FindData {
            public uint attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME created, accessed, written;
            public uint sizeHigh, sizeLow, reserved0, reserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)] public string name;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst=14)] public string alternate;
        }

        public static string KeyName(string directory) {
            if (directory == null || !Regex.IsMatch(directory,
                    "\\A" + Prefix + "[0-9a-f]{32}\\z", RegexOptions.CultureInvariant))
                throw new InvalidOperationException("Invalid reserved namespace");
            return "age-tpm-wsl-pq-" + directory.Substring(Prefix.Length);
        }

        public static bool RootAbsent(bool found, int error) {
            if (found) return false; // Includes reparse entries; do not follow the target.
            if (error == 2 || error == 3) return true;
            throw new InvalidOperationException("Directory observation failed");
        }

        public static bool KeyAbsent(int status) {
            if (status == 0) return false;
            if (status == BadKeyset) return true;
            throw new InvalidOperationException("PCP observation failed");
        }

        private static string LocalRoot() {
            Guid id = new Guid("F1B32785-6FBA-4FCF-9D55-7B8E7F157091");
            IntPtr path = IntPtr.Zero;
            try {
                int status = SHGetKnownFolderPath(ref id, 0, IntPtr.Zero, out path);
                if (status != 0 || path == IntPtr.Zero)
                    throw new InvalidOperationException("Known folder lookup failed");
                string value = Marshal.PtrToStringUni(path);
                if (String.IsNullOrEmpty(value) || !Path.IsPathRooted(value))
                    throw new InvalidOperationException("Invalid local application directory");
                return value;
            } finally {
                if (path != IntPtr.Zero) Marshal.FreeCoTaskMem(path);
            }
        }

        private static bool DirectoryAbsent(string path) {
            FindData data;
            IntPtr search = FindFirstFileW(path, out data);
            int error = Marshal.GetLastWin32Error();
            if (search == Invalid) return RootAbsent(false, error);
            if (!FindClose(search)) throw new InvalidOperationException("Search handle release failed");
            return RootAbsent(true, 0);
        }

        private static bool DedicatedKeyAbsent(string name) {
            IntPtr provider = IntPtr.Zero, key = IntPtr.Zero;
            int keyRelease = 0, providerRelease = 0;
            try {
                int status = NCryptOpenStorageProvider(out provider, "Microsoft Platform Crypto Provider", 0);
                if (status != 0 || provider == IntPtr.Zero)
                    throw new InvalidOperationException("Required PCP unavailable");
                status = NCryptOpenKey(provider, out key, name, 0, 0x40); // NCRYPT_SILENT_FLAG
                bool absent = KeyAbsent(status);
                if (!absent && key == IntPtr.Zero)
                    throw new InvalidOperationException("Invalid successful key handle");
                return absent;
            } finally {
                if (key != IntPtr.Zero) keyRelease = NCryptFreeObject(key);
                if (provider != IntPtr.Zero) providerRelease = NCryptFreeObject(provider);
                if (keyRelease != 0 || providerRelease != 0)
                    throw new InvalidOperationException("PCP handle release failed");
            }
        }

        public static Snapshot Read(string directory) {
            string name = KeyName(directory); // Validate before SID, filesystem or PCP access.
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) {
                if (identity.User == null) throw new InvalidOperationException("Missing Windows SID");
                return new Snapshot { sid = identity.User.Value,
                    root_absent = DirectoryAbsent(Path.Combine(LocalRoot(), directory)),
                    key_absent = DedicatedKeyAbsent(name) };
            }
        }
    }
}
'@

if ($SoftwareOnly) {
    # Exercise compiled pure code only. No SID/folder/provider/key query occurs.
    $cases = 0
    $prefix = 'age-tpm-wsl-post-quantum-client-'
    if ([DisposableClientObservation.Probe]::KeyName($Namespace) -cne ('age-tpm-wsl-pq-' + $Namespace.Substring($prefix.Length))) {
        throw 'Name derivation failed'
    }
    $cases++
    foreach ($invalid in @('', 'age-tpm-wsl', $Namespace.ToUpperInvariant(), ($Namespace + "`n"), ($Namespace + '/x'))) {
        $rejected = $false
        try { [void][DisposableClientObservation.Probe]::KeyName($invalid) } catch { $rejected = $true }
        if (-not $rejected) { throw 'Invalid namespace accepted' }
        $cases++
    }
    foreach ($missing in @(2, 3)) {
        if (-not [DisposableClientObservation.Probe]::RootAbsent($false, $missing)) { throw 'Missing path rejected' }
        $cases++
    }
    if ([DisposableClientObservation.Probe]::RootAbsent($true, 0)) { throw 'Existing entry classified absent' }
    $cases++
    foreach ($other in @(0, 5, 32, 123)) {
        $rejected = $false
        try { [void][DisposableClientObservation.Probe]::RootAbsent($false, $other) } catch { $rejected = $true }
        if (-not $rejected) { throw 'Unexpected path failure accepted' }
        $cases++
    }
    if ([DisposableClientObservation.Probe]::KeyAbsent(0)) { throw 'Existing key classified absent' }
    $cases++
    if (-not [DisposableClientObservation.Probe]::KeyAbsent(-2146893802)) { throw 'Missing key rejected' }
    $cases++
    foreach ($other in @(-2146893807, -2146893790, -1, 1)) {
        $rejected = $false
        try { [void][DisposableClientObservation.Probe]::KeyAbsent($other) } catch { $rejected = $true }
        if (-not $rejected) { throw 'Unexpected PCP failure accepted' }
        $cases++
    }
    [Console]::Out.WriteLine(('{"software_cases":' + $cases + ',"native_probe_called":false}'))
    exit 0
}

$value = [DisposableClientObservation.Probe]::Read($Namespace)
[Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject ([ordered]@{
    namespace = $Namespace
    name = [DisposableClientObservation.Probe]::KeyName($Namespace)
    sid = $value.sid
    root_absent = $value.root_absent
    key_absent = $value.key_absent
})))
