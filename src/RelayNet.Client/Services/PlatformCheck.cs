using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace RelayNet.Client.Services
{
    /// <summary>
    /// Validates OS + CPU architecture at startup and explains what native runtime (RID) is expected.
    /// This runs is RelayNet.Client (app layer), not in RelayNet.Tun.
    /// </summary>
    public static class PlatformCheck
    {
        public sealed record Result(
            bool isSupported, 
            string Os, 
            string Architecture,
            bool is64BitProcess,
            string? WindowsRid, 
            string Message
            );

        /// <summary>
        /// Call this at startup. if unsupported, throw with a clear message.
        /// </summary>
        /// 
        public static Result EnsureSupportedOrThrow()
        {
            var result = Check(); 
            if(!result.isSupported)
                throw new PlatformNotSupportedException(result.Message);

            return result;
        }

        /// <summary>
        /// Checks platform support without throwing.
        /// </summary>  
        /// 
        public static Result Check()
        { 
            var os = 
                OperatingSystem.IsWindows() ? "Windows" :
                OperatingSystem.IsLinux() ? "Linux" :
                OperatingSystem.IsMacOS() ? "macOS" :
                "Unknown";
            var arch = RuntimeInformation.ProcessArchitecture;
            var is64 = Environment.Is64BitProcess;

                if (os != "Windows")
                {
                    return new Result(
                        isSupported: false, 
                        Os: os, 
                        Architecture: arch.ToString(),
                        is64BitProcess: is64, 
                        WindowsRid: null, 
                        Message: $"TUN is currently supported on Windows (Wintun). Detected OS: {os}"
                        );
                }
                // Map arch -> expected Windows RID folder (runtimes/<rid>/native/wintun.dll)
                var rid = GetWindowsRidOrNull(arch);
                if (rid is null)
                { 
                  return new Result(
                        isSupported: false, 
                        Os: os, 
                        Architecture: arch.ToString(),
                        is64BitProcess: is64, 
                        WindowsRid: null, 
                        Message: $"Unsupported CPU architecture for Wintun. Detected: {arch}. Supported: X64, X86, Arm64, Arm."
                        );
                }
                // Sanity check: 32-bit process on 64-bit OS is allowed, but requires win-x86 DLL.
                // We report what the process needs (because native DLL must match the process).
                if (arch == Architecture.X64 && !is64)
                {
                    return new Result(
                        isSupported: false, 
                        Os: os,
                        Architecture: arch.ToString(),
                        is64BitProcess: is64,
                        WindowsRid: "win-x86",
                        Message: "Process is 32-bit but architecture is reported as X64. Ensure you are running a 64-bit build, or ship win-x86/native/wintun.dll and run as x86."
                        );
                }

                return new Result(
                    isSupported: true,
                    Os: os,
                    Architecture: arch.ToString(),
                    is64BitProcess: is64,
                    WindowsRid: rid,
                    Message: $"Supported platform. Use runtimes/{rid}/native/wintun.dll (process arch: {arch}, 64-bit process: {is64})"
                    );
        }
        /// <summary>
        ///  Maps process architecture to the Windows RID folder name used by .NET. runtime/ layout. 
        /// </summary>
        /// 
        private static string? GetWindowsRidOrNull(Architecture arch)
        {
            return arch switch
            {
                Architecture.X64 => "win-x64",
                Architecture.X86 => "win-x86",
                Architecture.Arm64 => "win-arm64",
                Architecture.Arm => "win-arm",
                _ => null,
            };
        }
    }
}
