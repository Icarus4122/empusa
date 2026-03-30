using System;
using System.Diagnostics;

/*
 * sharp-runner - C# Command Execution
 *
 * Runs arbitrary system commands. Useful as a base for C# payloads
 * that need to execute OS-level commands.
 *
 * Build: dotnet build -o build/ -c Release
 * Usage: sharp-runner.exe "whoami /all"
 */

namespace SharpRunner
{
    class Program
    {
        static void Main(string[] args)
        {
            string command = args.Length > 0 ? args[0] : "whoami /all";

            Console.WriteLine($"[*] Executing: {command}");

            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {command}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process proc = Process.Start(psi))
            {
                string output = proc.StandardOutput.ReadToEnd();
                string errors = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

                if (!string.IsNullOrEmpty(output))
                    Console.Write(output);
                if (!string.IsNullOrEmpty(errors))
                    Console.Error.Write(errors);
            }
        }
    }
}
