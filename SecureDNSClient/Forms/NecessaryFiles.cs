using CustomControls;
using MsmhToolsClass;
using System.Reflection;
using System.Runtime.InteropServices;

namespace SecureDNSClient;

public partial class FormMain : Form
{
    public bool CheckNecessaryFiles(bool showMessage = true)
    {
        if (!File.Exists(SecureDNS.SDCLookupPath) || !File.Exists(SecureDNS.AgnosticServerPath) ||
            !File.Exists(SecureDNS.DnsLookup) ||
            !File.Exists(SecureDNS.GoodbyeDpi) ||
            !File.Exists(SecureDNS.WinDivert) || !File.Exists(SecureDNS.WinDivert32) || !File.Exists(SecureDNS.WinDivert64))
        {
            if (showMessage)
            {
                string msg = "ERROR: Some Of Binary Files Are Missing!" + NL;
                this.InvokeIt(() => CustomRichTextBoxLog.AppendText(msg, Color.IndianRed));
            }
            return false;
        }
        else return true;
    }

    private async Task<bool> WriteNecessaryFilesToDisk()
    {
        bool success = true;
        Architecture arch = RuntimeInformation.ProcessArchitecture;

        // Get New Versions
        string dnslookupNewVer = SecureDNS.GetBinariesVersionFromResource("dnslookup", arch);
        string sdclookupNewVer = SecureDNS.GetBinariesVersionFromResource("sdclookup", arch);
        string sdcagnosticserverNewVer = SecureDNS.GetBinariesVersionFromResource("sdcagnosticserver", arch);
        string goodbyedpiNewVer = SecureDNS.GetBinariesVersionFromResource("goodbyedpi", arch);

        // Get Old Versions
        string dnslookupOldVer = SecureDNS.GetBinariesVersion("dnslookup", arch);
        string sdclookupOldVer = SecureDNS.GetBinariesVersion("sdclookup", arch);
        string sdcagnosticserverOldVer = SecureDNS.GetBinariesVersion("sdcagnosticserver", arch);
        string goodbyedpiOldVer = SecureDNS.GetBinariesVersion("goodbyedpi", arch);

        // Get Version Result
        int dnslookupResult = Info.VersionCompare(dnslookupNewVer, dnslookupOldVer);
        int sdclookupResult = Info.VersionCompare(sdclookupNewVer, sdclookupOldVer);
        int sdcagnosticserverResult = Info.VersionCompare(sdcagnosticserverNewVer, sdcagnosticserverOldVer);
        int goodbyedpiResult = Info.VersionCompare(goodbyedpiNewVer, goodbyedpiOldVer);

        // Fix GoodbyeDPI
        bool fixUpdateGoodbyDpi = false;
        try
        {
            int fixGoodbyeDpiResult = Info.VersionCompare("0.2.2", goodbyedpiOldVer);
            if (fixGoodbyeDpiResult == 0 && File.Exists(SecureDNS.WinDivert))
            {
                byte[] gdBytes = await File.ReadAllBytesAsync(SecureDNS.WinDivert);
                if (gdBytes.Length >= 30000) fixUpdateGoodbyDpi = true;
            }
        }
        catch (Exception) { }

        // Check Missing/Update Binaries
        if (!CheckNecessaryFiles(false) || dnslookupResult == 1 || sdclookupResult == 1 || sdcagnosticserverResult == 1 || goodbyedpiResult == 1 || fixUpdateGoodbyDpi)
        {
            string msg1 = $"Creating/Updating {arch} Binaries. Please Wait..." + NL;
            CustomRichTextBoxLog.AppendText(msg1, Color.LightGray);

            success = await writeBinariesAsync();
        }

        return success;

        async Task<bool> writeBinariesAsync()
        {
            try
            {
                if (!Directory.Exists(SecureDNS.BinaryDirPath))
                    Directory.CreateDirectory(SecureDNS.BinaryDirPath);

                if (!File.Exists(SecureDNS.DnsLookup) || dnslookupResult == 1)
                {
                    byte[] data = arch == Architecture.X64 ? NecessaryFiles.Resource1.dnslookup_X64 : NecessaryFiles.Resource1.dnslookup_X86;
                    if (!IsValidBinaryPayload(data))
                        throw new InvalidOperationException("Embedded dnslookup binary is missing/placeholder. Use an official release package or restore NecessaryFiles.");
                    await File.WriteAllBytesAsync(SecureDNS.DnsLookup, data);
                }

                if (!File.Exists(SecureDNS.SDCLookupPath) || sdclookupResult == 1)
                {
                    byte[] data = arch == Architecture.X64 ? NecessaryFiles.Resource1.SDCLookup_X64 : NecessaryFiles.Resource1.SDCLookup_X86;
                    if (!IsValidBinaryPayload(data))
                        throw new InvalidOperationException("Embedded SDCLookup binary is missing/placeholder. Use an official release package or restore NecessaryFiles.");
                    await File.WriteAllBytesAsync(SecureDNS.SDCLookupPath, data);
                }

                if (!File.Exists(SecureDNS.AgnosticServerPath) || sdcagnosticserverResult == 1)
                {
                    byte[] data = arch == Architecture.X64 ? NecessaryFiles.Resource1.SDCAgnosticServer_X64 : NecessaryFiles.Resource1.SDCAgnosticServer_X86;
                    if (!IsValidBinaryPayload(data))
                        throw new InvalidOperationException("Embedded SDCAgnosticServer binary is missing/placeholder. Use an official release package or restore NecessaryFiles.");
                    await File.WriteAllBytesAsync(SecureDNS.AgnosticServerPath, data);
                }

                if (goodbyedpiResult == 1 || fixUpdateGoodbyDpi)
                    await DeleteGoodbyeDpiAndWinDivertServices_Async();

                if (!File.Exists(SecureDNS.GoodbyeDpi) || goodbyedpiResult == 1 || fixUpdateGoodbyDpi)
                {
                    byte[] data = NecessaryFiles.Resource1.goodbyedpi;
                    if (!IsValidBinaryPayload(data))
                        throw new InvalidOperationException("Embedded goodbyedpi binary is missing/placeholder.");
                    await File.WriteAllBytesAsync(SecureDNS.GoodbyeDpi, data);
                }

                if (!File.Exists(SecureDNS.WinDivert) || fixUpdateGoodbyDpi)
                {
                    byte[] data = NecessaryFiles.Resource1.WinDivert;
                    if (!IsValidBinaryPayload(data))
                        throw new InvalidOperationException("Embedded WinDivert binary is missing/placeholder.");
                    await File.WriteAllBytesAsync(SecureDNS.WinDivert, data);
                }

                if (!File.Exists(SecureDNS.WinDivert32) || fixUpdateGoodbyDpi)
                    await File.WriteAllBytesAsync(SecureDNS.WinDivert32, NecessaryFiles.Resource1.WinDivert32);

                if (!File.Exists(SecureDNS.WinDivert64) || fixUpdateGoodbyDpi)
                    await File.WriteAllBytesAsync(SecureDNS.WinDivert64, NecessaryFiles.Resource1.WinDivert64);

                // Update Old Version Numbers
                await File.WriteAllBytesAsync(SecureDNS.BinariesVersionPath, NecessaryFiles.Resource1.versions);

                string msgWB = $"{Info.GetAppInfo(Assembly.GetExecutingAssembly()).ProductName} Is Ready.{NL}";
                this.InvokeIt(() => CustomRichTextBoxLog.AppendText(msgWB, Color.LightGray));

                return true;
            }
            catch (Exception ex)
            {
                string msg = $"{ex.Message}{NL}";
                msg += $"Couldn't write binaries to disk.{NL}";
                msg += "Please End Task the problematic process from Task Manager and Restart the Application.";
                CustomMessageBox.Show(this, msg, "Write Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }
    }

    /// <summary>Rejects git placeholder stubs (e.g. 11-byte "Placeholder") so we never write a broken AgnosticServer.</summary>
    private static bool IsValidBinaryPayload(byte[]? data) => data != null && data.Length >= 1024;

}