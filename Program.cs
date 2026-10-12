using System;
using System.Diagnostics;
using RescueKit;

namespace RescueKit
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("=================================================");
            Console.WriteLine("       Windows Rescue & Repair Toolkit v1.0      ");
            Console.WriteLine("=================================================");
            Console.ResetColor();

            if (args.Length > 0 && args[0].ToLowerInvariant() == "--all")
            {
                RunAllRepairs();
                return;
            }

            Console.WriteLine("1. Снять системные запреты (TaskMgr, Regedit, CMD, GP)");
            Console.WriteLine("2. Очистить перехваты запуска IFEO (Debugger/GlobalFlag)");
            Console.WriteLine("3. Восстановить оболочку Winlogon и AppInit_DLLs");
            Console.WriteLine("4. Восстановить ассоциации файлов (.exe, .lnk, .bat...)");
            Console.WriteLine("5. Выполнить полное автоматическое восстановление");
            Console.WriteLine("6. Список активных неподписанных процессов");
            Console.WriteLine("0. Выход");
            Console.Write("\nВыберите действие [1-6, 0]: ");

            string? choice = Console.ReadLine()?.Trim();
            Console.WriteLine();

            switch (choice)
            {
                case "1":
                    Repair.UnlockSystemTools(LogMessage);
                    break;
                case "2":
                    Repair.FixIfeo(LogMessage);
                    break;
                case "3":
                    Repair.FixShell(LogMessage);
                    break;
                case "4":
                    Repair.FixFileAssociations(LogMessage);
                    break;
                case "5":
                    RunAllRepairs();
                    break;
                case "6":
                    ScanProcesses();
                    break;
                default:
                    Console.WriteLine("Выход.");
                    break;
            }
        }

        static void LogMessage(string msg)
        {
            if (msg.StartsWith("[+]")) Console.ForegroundColor = ConsoleColor.Green;
            else if (msg.StartsWith("[*]")) Console.ForegroundColor = ConsoleColor.Cyan;
            else if (msg.StartsWith("  удален") || msg.StartsWith("  снят")) Console.ForegroundColor = ConsoleColor.Yellow;
            else if (msg.StartsWith("  ошибка") || msg.StartsWith("  [!]")) Console.ForegroundColor = ConsoleColor.Red;
            else Console.ResetColor();

            Console.WriteLine(msg);
            Console.ResetColor();
        }

        static void RunAllRepairs()
        {
            Console.WriteLine("[*] Запуск комплексного восстановления системы...\n");
            Repair.UnlockSystemTools(LogMessage);
            Console.WriteLine();
            Repair.FixIfeo(LogMessage);
            Console.WriteLine();
            Repair.FixShell(LogMessage);
            Console.WriteLine();
            Repair.FixFileAssociations(LogMessage);
            Console.WriteLine("\n[+] Комплексное восстановление завершено!");
        }

        static void ScanProcesses()
        {
            Console.WriteLine("[*] Сканирование запущенных процессов на цифровую подпись...");
            var processes = Process.GetProcesses();
            int unsignedCount = 0;

            foreach (var p in processes)
            {
                try
                {
                    string path = Native.GetProcessPath(p.Id);
                    if (string.IsNullOrWhiteSpace(path)) continue;

                    var sig = Native.CheckSignature(path);
                    if (sig != Native.SigState.Signed)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"  [PID {p.Id}] {p.ProcessName} -> {path} ({sig})");
                        Console.ResetColor();
                        unsignedCount++;
                    }
                }
                catch { }
            }

            Console.WriteLine($"\n[+] Проверка завершена. Неподписанных процессов: {unsignedCount}");
        }
    }
}
