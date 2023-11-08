using CliWrap;
using SharpCompress.Readers;
using System.Runtime.InteropServices;
using System.Text;
using CliWrap.Buffered;

namespace oidc_guard_tests.EndToEnd
{
    public class Helm
    {
        private const string Version = "3.12.3";

        public static string FileName { get; } = "helm" + (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? ".exe" : "");

        public static async Task DownloadClient()
        {
            if (File.Exists(FileName)) return;

            using var client = new HttpClient();
            var arch = "amd64";

            if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
            {
                arch = "arm64";
            }

            var os = "linux";

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                os = "darwin";
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                os = "windows";
            }

            var url = $"https://get.helm.sh/helm-v{Version}-{os}-{arch}.{(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "zip" : "tar.gz")}";

            using var stream = await client.GetStreamAsync(url);
            using var reader = ReaderFactory.Open(stream);
            while (reader.MoveToNextEntry())
            {
                if (!reader.Entry.IsDirectory && reader.Entry.Key.EndsWith(FileName))
                {
                    reader.WriteEntryToFile(FileName);
                    break;
                }
            }

            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                await Cli.Wrap("chmod")
                    .WithArguments("+x ./helm")
                    .ExecuteAsync();
            }
        }

        public static async Task RepoAdd(string name, string url)
        {
            await Cli.Wrap(FileName)
                .WithArguments(new[] { "repo", "add", name, url })
                .WithStandardOutputPipe(PipeTarget.ToDelegate(Console.WriteLine))
                .WithStandardErrorPipe(PipeTarget.ToDelegate(Console.WriteLine))
                .ExecuteBufferedAsync();
        }

        public static async Task RepoRemove(string name)
        {
            await Cli.Wrap(FileName)
                .WithArguments(new[] { "repo", "remove", name })
                .WithValidation(CommandResultValidation.None)
                .WithStandardOutputPipe(PipeTarget.ToDelegate(Console.WriteLine))
                .WithStandardErrorPipe(PipeTarget.ToDelegate(Console.WriteLine))
                .ExecuteBufferedAsync();
        }

        public static async Task RepoUpdate()
        {
            await Cli.Wrap(FileName)
                .WithArguments(new[] { "repo", "update" })
                .WithStandardOutputPipe(PipeTarget.ToDelegate(Console.WriteLine))
                .WithStandardErrorPipe(PipeTarget.ToDelegate(Console.WriteLine))
                .ExecuteBufferedAsync();
        }

        public static async Task Install(string name, string chart, string flags)
        {
            var stdErrBuffer = new StringBuilder();
            await Cli.Wrap(FileName)
            .WithArguments($"install {name} {chart} {flags}")
            .WithStandardErrorPipe(PipeTarget.ToStringBuilder(stdErrBuffer))
            .ExecuteAsync();

            var stdErr = stdErrBuffer.ToString();

            if (!string.IsNullOrEmpty(stdErr))
            {
                throw new Exception(stdErr);
            }
        }

        public static async Task Upgrade(string name, string chart, string flags)
        {
            var stdErrBuffer = new StringBuilder();
            await Cli.Wrap(FileName)
            .WithArguments($"upgrade {name} {chart} {flags}")
            .WithStandardErrorPipe(PipeTarget.ToStringBuilder(stdErrBuffer))
            .ExecuteAsync();

            var stdErr = stdErrBuffer.ToString();

            if (!string.IsNullOrEmpty(stdErr))
            {
                throw new Exception(stdErr);
            }
        }
    }
}
