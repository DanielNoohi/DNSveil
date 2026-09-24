using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecureDNSClient.GeoHide;

/// <summary>Owns exactly one backend process tree; the Windows job kills it if DNSveil exits.</summary>
internal sealed class OwnedBackendProcess : IAsyncDisposable
{
    private readonly Process process;
    private readonly SafeFileHandle job;
    private readonly Task outputDrain;
    private readonly Task errorDrain;
    internal bool Running => !process.HasExited;

    internal OwnedBackendProcess(string executable, params string[] arguments)
    {
        job = CreateJobObject(IntPtr.Zero, null);
        if (job.IsInvalid) throw new Win32Exception();
        var limits = new JobExtendedLimits { Basic = new JobBasicLimits { Flags = 0x2000 } }; // KILL_ON_JOB_CLOSE
        if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<JobExtendedLimits>()))
        { job.Dispose(); throw new Win32Exception(); }
        process = new Process { StartInfo = new ProcessStartInfo {
            FileName = executable, WorkingDirectory = Path.GetDirectoryName(executable)!, UseShellExecute = false,
            CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        } };
        foreach (string argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        try
        {
            process.Start();
            if (!AssignProcessToJobObject(job, process.Handle)) throw new Win32Exception();
            // Drain without retaining traffic metadata, credentials, or unbounded output.
            outputDrain = DrainAsync(process.StandardOutput);
            errorDrain = DrainAsync(process.StandardError);
        }
        catch
        {
            try { if (!process.HasExited) process.Kill(true); } catch { }
            process.Dispose(); job.Dispose(); throw;
        }
    }
    private static async Task DrainAsync(StreamReader reader)
    {
        char[] buffer = new char[2048];
        while (await reader.ReadAsync(buffer.AsMemory()).ConfigureAwait(false) != 0) { }
    }
    public async ValueTask DisposeAsync()
    {
        job.Dispose();
        if (!process.HasExited) { try { process.Kill(true); } catch (InvalidOperationException) { } }
        await process.WaitForExitAsync().ConfigureAwait(false);
        await Task.WhenAll(outputDrain, errorDrain).ConfigureAwait(false);
        process.Dispose();
    }
    [StructLayout(LayoutKind.Sequential)] private struct JobBasicLimits {
        public long ProcessTime, JobTime; public uint Flags; public UIntPtr MinWorkingSet, MaxWorkingSet;
        public uint ActiveProcesses; public UIntPtr Affinity; public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] private struct JobExtendedLimits {
        public JobBasicLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateJobObject(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref JobExtendedLimits info, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
}
