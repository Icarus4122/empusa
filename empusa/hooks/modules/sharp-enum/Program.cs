using System;
using System.Diagnostics;

/*
 * sharp-enum - C# Host Enumeration
 *
 * Runs common enumeration commands and prints all output.
 * Useful when PowerShell is blocked or constrained language mode is active.
 *
 * Build:  dotnet build -o build/ -c Release
 * Usage:  sharp-enum.exe
 *
 */

namespace SharpEnum
{
    class Program
    {
        static string[] commands = new string[]
        {
            "whoami",
            "whoami /priv",
            "whoami /groups",
            "net user",
            "net localgroup Administrators",
            "systeminfo",
            "ipconfig /all",
            "route print",
            "netstat -ano",
            "tasklist /v",
            "schtasks /query /fo LIST /v",
            "wmic service get name,pathname,startmode | findstr /i /v \"C:\\Windows\\\\\"",
        };

        static void Main(string[] args)
        {
            foreach (string cmd in commands)
            {
                Console.WriteLine($"\n{'=',0} {cmd} {'=',0}");
                Console.WriteLine(new string('=', cmd.Length + 4));

                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = $"/c {cmd}",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using (Process proc = Process.Start(psi))
                    {
                        Console.Write(proc.StandardOutput.ReadToEnd());
                        string err = proc.StandardError.ReadToEnd();
                        if (!string.IsNullOrEmpty(err))
                            Console.Error.Write(err);
                        proc.WaitForExit();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[!] Error: {ex.Message}");
                }
            }
        }
    }
}
