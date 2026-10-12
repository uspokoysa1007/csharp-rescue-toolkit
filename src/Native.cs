using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace RescueKit
{
    /// <summary>WinAPI helpers: suspend/resume processes, digital signature checks, hashing.</summary>
    internal static class Native
    {
        [DllImport("ntdll.dll")] static extern int NtSuspendProcess(IntPtr h);
        [DllImport("ntdll.dll")] static extern int NtResumeProcess(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder sb, ref int size);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr h, uint code);

        const uint PROCESS_SUSPEND_RESUME = 0x0800;
        const uint PROCESS_TERMINATE = 0x0001;
        const uint PROCESS_QUERY_LIMITED = 0x1000;

        public static bool Suspend(int pid) { return CallOnProcess(pid, true); }
        public static bool Resume(int pid) { return CallOnProcess(pid, false); }

        static bool CallOnProcess(int pid, bool suspend)
        {
            IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
            if (h == IntPtr.Zero) return false;
            try { return (suspend ? NtSuspendProcess(h) : NtResumeProcess(h)) == 0; }
            finally { CloseHandle(h); }
        }

        public static bool Terminate(int pid)
        {
            IntPtr h = OpenProcess(PROCESS_TERMINATE, false, pid);
            if (h == IntPtr.Zero) return false;
            try { return TerminateProcess(h, 1); }
            finally { CloseHandle(h); }
        }

        /// <summary>Gets the exe path even for processes where Process.MainModule throws (32/64-bit, protected).</summary>
        public static string GetProcessPath(int pid)
        {
            IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED, false, pid);
            if (h == IntPtr.Zero) return "";
            try
            {
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : "";
            }
            finally { CloseHandle(h); }
        }

        // ---------------- Signature verification (embedded + catalog) ----------------

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct;
            public uint dwCatalogVersion;
            public string pcwszCatalogFilePath;
            public string pcwszMemberTag;
            public string pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pInfo;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);
        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminAcquireContext(out IntPtr hAdmin, IntPtr subsystem, uint flags);
        [DllImport("wintrust.dll")]
        static extern bool CryptCATAdminReleaseContext(IntPtr hAdmin, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint cbHash, byte[] hash, uint flags);
        [DllImport("wintrust.dll")]
        static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hAdmin, byte[] hash, uint cbHash, uint flags, IntPtr prev);
        [DllImport("wintrust.dll")]
        static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO info, uint flags);
        [DllImport("wintrust.dll")]
        static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hAdmin, IntPtr hCatInfo, uint flags);

        static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        public enum SigState { Unknown, Signed, Unsigned, Invalid, Missing }

        public static SigState CheckSignature(string path)
        {
            if (string.IsNullOrEmpty(path)) return SigState.Unknown;
            if (!File.Exists(path)) return SigState.Missing;
            try
            {
                int r = VerifyEmbedded(path);
                if (r == 0) return SigState.Signed;
                if (VerifyCatalog(path)) return SigState.Signed;
                // TRUST_E_NOSIGNATURE / TRUST_E_SUBJECT_FORM_UNKNOWN / TRUST_E_PROVIDER_UNKNOWN
                if (r == unchecked((int)0x800B0100) || r == unchecked((int)0x800B0003) || r == unchecked((int)0x800B0001))
                    return SigState.Unsigned;
                return SigState.Invalid;
            }
            catch { return SigState.Unknown; }
        }

        static int VerifyEmbedded(string path)
        {
            var fi = new WINTRUST_FILE_INFO();
            fi.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            fi.pcwszFilePath = path;
            IntPtr pFi = Marshal.AllocHGlobal(Marshal.SizeOf(fi));
            Marshal.StructureToPtr(fi, pFi, false);
            try { return RunTrust(1, pFi); }
            finally { Marshal.DestroyStructure(pFi, typeof(WINTRUST_FILE_INFO)); Marshal.FreeHGlobal(pFi); }
        }

        static bool VerifyCatalog(string path)
        {
            IntPtr hAdmin;
            if (!CryptCATAdminAcquireContext(out hAdmin, IntPtr.Zero, 0)) return false;
            try
            {
                byte[] hash;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    IntPtr hFile = fs.SafeFileHandle.DangerousGetHandle();
                    uint cb = 0;
                    CryptCATAdminCalcHashFromFileHandle(hFile, ref cb, null, 0);
                    if (cb == 0) return false;
                    hash = new byte[cb];
                    if (!CryptCATAdminCalcHashFromFileHandle(hFile, ref cb, hash, 0)) return false;
                }
                IntPtr hCat = CryptCATAdminEnumCatalogFromHash(hAdmin, hash, (uint)hash.Length, 0, IntPtr.Zero);
                if (hCat == IntPtr.Zero) return false;
                try
                {
                    var ci = new CATALOG_INFO();
                    ci.cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO));
                    if (!CryptCATCatalogInfoFromContext(hCat, ref ci, 0)) return false;

                    var sbTag = new StringBuilder();
                    foreach (byte b in hash) sbTag.Append(b.ToString("X2"));

                    var cat = new WINTRUST_CATALOG_INFO();
                    cat.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO));
                    cat.pcwszCatalogFilePath = ci.wszCatalogFile;
                    cat.pcwszMemberTag = sbTag.ToString();
                    cat.pcwszMemberFilePath = path;
                    cat.hCatAdmin = hAdmin;
                    IntPtr pCat = Marshal.AllocHGlobal(Marshal.SizeOf(cat));
                    Marshal.StructureToPtr(cat, pCat, false);
                    try { return RunTrust(2, pCat) == 0; }
                    finally { Marshal.DestroyStructure(pCat, typeof(WINTRUST_CATALOG_INFO)); Marshal.FreeHGlobal(pCat); }
                }
                finally { CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0); }
            }
            catch { return false; }
            finally { CryptCATAdminReleaseContext(hAdmin, 0); }
        }

        static int RunTrust(uint unionChoice, IntPtr pInfo)
        {
            var d = new WINTRUST_DATA();
            d.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
            d.dwUIChoice = 2;            // WTD_UI_NONE
            d.fdwRevocationChecks = 0;   // WTD_REVOKE_NONE (works offline)
            d.dwUnionChoice = unionChoice;
            d.pInfo = pInfo;
            d.dwStateAction = 1;         // WTD_STATEACTION_VERIFY
            d.dwProvFlags = 0x00001000;  // WTD_CACHE_ONLY_URL_RETRIEVAL
            Guid g = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            int r = WinVerifyTrust(IntPtr.Zero, ref g, ref d);
            d.dwStateAction = 2;         // WTD_STATEACTION_CLOSE
            WinVerifyTrust(IntPtr.Zero, ref g, ref d);
            return r;
        }

        public static string Sha256(string path)
        {
            using (var sha = SHA256.Create())
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var sb = new StringBuilder();
                foreach (byte b in sha.ComputeHash(fs)) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }
    }
}
