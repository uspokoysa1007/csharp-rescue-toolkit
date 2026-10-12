using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using Microsoft.Win32;

namespace RescueKit
{
    /// <summary>Restores Windows settings that are commonly locked down by malware.</summary>
    internal static class Repair
    {
        public delegate void Log(string msg);

        public static RegistryKey Base(RegistryHive hive)
        {
            return RegistryKey.OpenBaseKey(hive, Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
        }

        public static string HiveName(RegistryHive h)
        {
            if (h == RegistryHive.LocalMachine) return "HKLM";
            if (h == RegistryHive.CurrentUser) return "HKCU";
            if (h == RegistryHive.ClassesRoot) return "HKCR";
            return h.ToString();
        }

        static void DeleteValues(RegistryHive hive, string path, string[] names, Log log)
        {
            try
            {
                using (var k = Base(hive).OpenSubKey(path, true))
                {
                    if (k == null) return;
                    foreach (var n in names)
                    {
                        if (k.GetValue(n) == null) continue;
                        k.DeleteValue(n, false);
                        log("  удалено: " + HiveName(hive) + "\\" + path + " -> " + n);
                    }
                }
            }
            catch (Exception ex) { log("  ошибка " + path + ": " + ex.Message); }
        }

        static void DeleteKey(RegistryHive hive, string path, Log log)
        {
            try
            {
                using (var b = Base(hive))
                {
                    using (var k = b.OpenSubKey(path)) { if (k == null) return; }
                    b.DeleteSubKeyTree(path, false);
                }
                log("  удалён раздел: " + HiveName(hive) + "\\" + path);
            }
            catch (Exception ex) { log("  ошибка " + path + ": " + ex.Message); }
        }

        static void SetValue(RegistryHive hive, string path, string name, object val, RegistryValueKind kind, Log log)
        {
            try
            {
                using (var k = Base(hive).CreateSubKey(path))
                {
                    object cur = k.GetValue(name);
                    if (cur != null && cur.ToString() == val.ToString()) return;
                    k.SetValue(name, val, kind);
                    log("  установлено: " + HiveName(hive) + "\\" + path + " -> " + name + " = " + val);
                }
            }
            catch (Exception ex) { log("  ошибка " + path + ": " + ex.Message); }
        }

        static readonly RegistryHive[] Both = { RegistryHive.CurrentUser, RegistryHive.LocalMachine };

        const string PolSystem = @"Software\Microsoft\Windows\CurrentVersion\Policies\System";
        const string PolExplorer = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";

        public static void UnlockSystemTools(Log log)
        {
            log("[*] Снятие запретов: диспетчер задач, regedit, cmd, панель управления, Win+R...");
            foreach (var h in Both)
            {
                DeleteValues(h, PolSystem, new[] {
                    "DisableTaskMgr", "DisableRegistryTools", "DisableLockWorkstation", "DisableChangePassword",
                    "DisableSwitchUserOption", "NoDispCPL", "NoDispAppearancePage", "NoDispBackgroundPage" }, log);
                DeleteValues(h, @"Software\Policies\Microsoft\Windows\System", new[] { "DisableCMD" }, log);
                DeleteValues(h, @"Software\Policies\Microsoft\MMC", new[] { "RestrictToPermittedSnapins" }, log);
                DeleteValues(h, PolExplorer, new[] {
                    "NoRun", "NoFolderOptions", "NoControlPanel", "NoDrives", "NoViewOnDrive", "NoClose", "NoDesktop",
                    "NoFind", "NoTrayContextMenu", "NoViewContextMenu", "NoLogoff", "DisallowRun", "RestrictRun",
                    "NoWinKeys", "NoFileMenu", "NoSetFolders", "NoSetTaskbar", "NoStartMenuMorePrograms", "NoManageMyComputerVerb",
                    "NoSecurityTab", "NoShellSearchButton", "HideClock", "NoTrayItemsDisplay", "NoChangeStartMenu",
                    "NoPropertiesMyComputer", "NoRecentDocsMenu", "NoDriveTypeAutoRun" }, log);
                DeleteKey(h, PolExplorer + @"\DisallowRun", log);
                DeleteKey(h, PolExplorer + @"\RestrictRun", log);
                DeleteKey(h, @"Software\Policies\Microsoft\Windows\Safer", log);
            }
            log("[+] Готово.");
        }

        static readonly string[] RescueTools = {
            "taskmgr.exe", "regedit.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "msconfig.exe", "mmc.exe",
            "explorer.exe", "rstrui.exe", "procexp.exe", "procexp64.exe", "autoruns.exe", "autoruns64.exe",
            "msmpeng.exe", "mpcmdrun.exe", "msascui.exe", "securityhealthsystray.exe", "windowsdefender.exe",
            "control.exe", "notepad.exe", "sfc.exe", "dism.exe", "perfmon.exe", "resmon.exe", "regedt32.exe",
            "mrt.exe", "secpol.msc", "gpedit.msc", "services.exe", "msinfo32.exe", "systemsettings.exe",
            "rescuekit.exe", "mbam.exe", "adwcleaner.exe", "kvrt.exe", "cureit.exe", "hijackthis.exe" };

        /// <summary>Removes "Debugger" hijacks (IFEO) that prevent tools/antivirus from starting.</summary>
        public static void FixIfeo(Log log)
        {
            log("[*] Проверка Image File Execution Options (перехват запуска программ)...");
            string[] roots = {
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" };
            foreach (var root in roots)
            {
                try
                {
                    using (var k = Base(RegistryHive.LocalMachine).OpenSubKey(root, true))
                    {
                        if (k == null) continue;
                        foreach (var sub in k.GetSubKeyNames())
                        {
                            using (var s = k.OpenSubKey(sub, true))
                            {
                                if (s == null) continue;
                                bool isRescue = Array.IndexOf(RescueTools, sub.ToLowerInvariant()) >= 0;
                                object dbg = s.GetValue("Debugger");
                                if (dbg != null && isRescue)
                                {
                                    s.DeleteValue("Debugger", false);
                                    log("  снят перехват: " + sub + " -> " + dbg);
                                }
                                else if (dbg != null)
                                {
                                    log("  [!] найден Debugger у " + sub + " -> " + dbg + " (см. вкладку Автозагрузка)");
                                }
                                // Silent process exit monitor (used to relaunch malware when something is killed)
                                if (s.GetValue("GlobalFlag") != null && isRescue)
                                {
                                    s.DeleteValue("GlobalFlag", false);
                                    log("  удалён GlobalFlag у " + sub);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex) { log("  ошибка: " + ex.Message); }
            }
            log("[+] Готово.");
        }

        public static void FixShell(Log log)
        {
            log("[*] Восстановление оболочки Winlogon (Shell / Userinit) и AppInit_DLLs...");
            string sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
            const string wl = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
            SetValue(RegistryHive.LocalMachine, wl, "Shell", "explorer.exe", RegistryValueKind.String, log);
            SetValue(RegistryHive.LocalMachine, wl, "Userinit", sys32 + "\\userinit.exe,", RegistryValueKind.String, log);
            DeleteValues(RegistryHive.CurrentUser, wl, new[] { "Shell", "Userinit" }, log);
            DeleteValues(RegistryHive.LocalMachine, wl, new[] { "Taskman", "AppSetup" }, log);
            foreach (var p in new[] { @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" })
            {
                SetValue(RegistryHive.LocalMachine, p, "AppInit_DLLs", "", RegistryValueKind.String, log);
                SetValue(RegistryHive.LocalMachine, p, "LoadAppInit_DLLs", 0, RegistryValueKind.DWord, log);
            }
            log("[+] Готово.");
        }

        public static void FixFileAssociations(Log log)
        {
            log("[*] Восстановление ассоциаций .exe .bat .cmd .com .lnk .reg .msi ...");
            var hkcr = RegistryHive.LocalMachine;
            const string cls = @"SOFTWARE\Classes\";
            SetValue(hkcr, cls + ".exe", "", "exefile", RegistryValueKind.String, log);
            SetValue(hkcr, cls + @"exefile\shell\open\command", "", "\"%1\" %*", RegistryValueKind.String, log);
            SetValue(hkcr, cls + ".com", "", "comfile", RegistryValueKind.String, log);
            SetValue(hkcr, cls + @"comfile\shell\open\command", "", "\"%1\" %*", RegistryValueKind.String, log);
            SetValue(hkcr, cls + ".bat", "", "batfile", RegistryValueKind.String, log);
            SetValue(hkcr, cls + @"batfile\shell\open\command", "", "\"%1\" %*", RegistryValueKind.String, log);
            SetValue(hkcr, cls + ".cmd", "", "cmdfile", RegistryValueKind.String, log);
            SetValue(hkcr, cls + @"cmdfile\shell\open\command", "", "\"%1\" %*", RegistryValueKind.String, log);
            SetValue(hkcr, cls + ".lnk", "", "lnkfile", RegistryValueKind.String, log);
            SetValue(hkcr, cls + ".reg", "", "regfile", RegistryValueKind.String, log);
            SetValue(hkcr, cls + @"regfile\shell\open\command", "", "regedit.exe \"%1\"", RegistryValueKind.String, log);
            SetValue(hkcr, cls + ".msi", "", "Msi.Package", RegistryValueKind.String, log);
            SetValue(hkcr, cls + @"Msi.Package\shell\open\command", "", "msiexec.exe /i \"%1\" %*", RegistryValueKind.String, log);
            log("[+] Готово.");
        }
    }
}
