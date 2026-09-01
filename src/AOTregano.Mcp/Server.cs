using System.Text.Json.Nodes;
using AOTregano.Core;

namespace AOTregano.Mcp;

internal sealed class Server(Rpc rpc)
{
    private static readonly string[] ProtocolVersions =
        ["2025-06-18", "2025-03-26", "2024-11-05"];

    public void Serve()
    {
        while (rpc.Read() is { } message)
        {
            var method = message["method"]?.GetValue<string>();
            var id = message["id"];
            if (method is null || id is null)
                continue;
            try
            {
                Answer(method, id, message["params"] as JsonObject);
            }
            catch (Exception exception)
            {
                rpc.Refuse(id, -32603, $"{exception.GetType().Name}: {exception.Message}");
            }
        }
    }

    private void Answer(string method, JsonNode id, JsonObject? parameters)
    {
        switch (method)
        {
            case "initialize":
                var requested = parameters?["protocolVersion"]?.GetValue<string>();
                rpc.Reply(id, new JsonObject
                {
                    ["protocolVersion"] = requested is not null &&
                        ProtocolVersions.Contains(requested) ? requested : ProtocolVersions[0],
                    ["capabilities"] = new JsonObject { ["tools"] = new JsonObject() },
                    ["serverInfo"] = new JsonObject
                    {
                        ["name"] = "aotregano",
                        ["version"] = AOTreganoAnalyzer.Version
                    },
                    ["instructions"] =
                        "Statically inspect x64 .NET NativeAOT PE and ELF files without executing " +
                        "them. Call analyze_nativeaot with an explicit local path."
                });
                break;
            case "ping":
                rpc.Reply(id, new JsonObject());
                break;
            case "tools/list":
                rpc.Reply(id, new JsonObject { ["tools"] = Tools.Listed() });
                break;
            case "tools/call":
                rpc.Reply(id, Tools.Call(parameters));
                break;
            case "resources/list":
                rpc.Reply(id, new JsonObject { ["resources"] = new JsonArray() });
                break;
            case "prompts/list":
                rpc.Reply(id, new JsonObject { ["prompts"] = new JsonArray() });
                break;
            default:
                rpc.Refuse(id, -32601, $"This server has no {method}.");
                break;
        }
    }
}
