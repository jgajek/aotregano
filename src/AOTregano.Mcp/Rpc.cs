using System.Text.Json;
using System.Text.Json.Nodes;

namespace AOTregano.Mcp;

internal sealed class Rpc(TextReader input, TextWriter output)
{
    public JsonObject? Read()
    {
        while (input.ReadLine() is { } line)
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;
            try
            {
                if (JsonNode.Parse(line) is JsonObject message)
                    return message;
            }
            catch (JsonException)
            {
                Console.Error.WriteLine("aotregano-mcp: ignoring a line that is not JSON.");
            }
        }
        return null;
    }

    public void Reply(JsonNode? id, JsonNode? result) => Send(new JsonObject
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id?.DeepClone(),
        ["result"] = result
    });

    public void Refuse(JsonNode? id, int code, string message) => Send(new JsonObject
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id?.DeepClone(),
        ["error"] = new JsonObject { ["code"] = code, ["message"] = message }
    });

    private void Send(JsonObject message)
    {
        output.WriteLine(message.ToJsonString());
        output.Flush();
    }
}
