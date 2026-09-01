using AOTregano.Core;

namespace AOTregano.Mcp;

internal static class Program
{
    public static int Main(string[] args)
    {
        if (args.Any(argument => argument is "-h" or "--help" or "/?"))
        {
            Console.Error.WriteLine(
                "AOTregano MCP " + AOTreganoAnalyzer.Version + Environment.NewLine +
                "Model Context Protocol server over standard input/output. Configure an MCP " +
                "client to launch aotregano-mcp; do not use it as an interactive CLI.");
            return 0;
        }
        if (args.Contains("--version", StringComparer.Ordinal))
        {
            Console.WriteLine(AOTreganoAnalyzer.Version);
            return 0;
        }

        new Server(new Rpc(Console.In, Console.Out)).Serve();
        return 0;
    }
}
