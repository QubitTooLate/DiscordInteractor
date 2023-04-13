using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Minecraft.Relay;
using NSec.Cryptography;
using System;
using System.Buffers;
using System.Net.Http;
using System.Net.Mime;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;

const string APP_ID = "";
const string GUILD_ID = "";
const string DISCORD_TOKEN = "";
const string PUBLIC_KEY = "";

var createGuildCommandUri = new Uri($"https://discord.com/api/v10/applications/{APP_ID}/guilds/{GUILD_ID}/commands");
var authorization = $"Bot {DISCORD_TOKEN}";

const int MAX_BODY_SIZE = 4096;

const string BODY_BUFFER_KEY = "BodyBufferKey";
const string BODY_BUFFER_LENGTH_KEY = "BodyBufferLengthKey";

const int SIGNATURE_LENGTH = 512 / 8;
const int MAX_TIMESTAMP_LENGTH = 64 / 8;

using var client = new HttpClient();

await CreateGuildCommandAsync();

var publicKey = PublicKey.Import(
    SignatureAlgorithm.Ed25519,
    Convert.FromHexString(PUBLIC_KEY),
    KeyBlobFormat.RawPublicKey
);

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;
var app = builder.Build();

app.Use(InteractionSignatureVerificationMiddleware);

app.MapPost("/interactions", Interactions);

app.Run();

return;

async Task CreateGuildCommandAsync()
{
    using var createCommandRequest = new HttpRequestMessage()
    {
        Method = HttpMethod.Post,
        RequestUri = createGuildCommandUri,
        Content = new StringContent(
            """
                {
                    "name": "test",
                    "description": "Test the bot.",
                    "type": 1
                }
                """,
            Encoding.UTF8,
            MediaTypeNames.Application.Json
        )
    };

    createCommandRequest.Headers.Add("Authorization", authorization);
    createCommandRequest.Headers.Add("User-Agent", "DiscordBot (Herobrine 1.0.0)");

    using var responseStopCommand = await client.SendAsync(createCommandRequest);
}

IResult Interactions(HttpRequest request)
{
    var bodyBuffer = GetBodyBuffer(request.HttpContext);
    var jsonNode = JsonSerializer.Deserialize<JsonNode>(bodyBuffer.Span);

    var type = (int?)jsonNode?["type"] ?? 0;
    var command = (string?)jsonNode?["data"]?["name"] ?? string.Empty;

    return (type, command) switch
    {
        (1, _) => GetRawJsonResult("""
                {
                    "type": 1
                }
                """),
        (2, "test") => GetRawJsonResult("""
                {
                    "type": 4,
                    "data": {
                        "content": "Hello, world!"
                    }
                }
                """),
        _ => Results.BadRequest()
    };
}

// If the request is not an interaction, it goes trough.
// If the request is an interaction and cannot be verified it returns UnAuthorized 401
// If the interaction is verified the body can be read from GetBodyBuffer.
async Task InteractionSignatureVerificationMiddleware(HttpContext context, Func<Task> next)
{
    var request = context.Request;
    var response = context.Response;

    if (IsInteraction(request))
    {
        using var signatureBufferScope = MemoryPool<byte>.Shared.Rent(SIGNATURE_LENGTH + MAX_TIMESTAMP_LENGTH);
        var signatureBuffer = signatureBufferScope.Memory[..SIGNATURE_LENGTH];
        var timestampBuffer = signatureBufferScope.Memory[SIGNATURE_LENGTH..];

        if (TryGetSignature(request, signatureBuffer, timestampBuffer, out var timestampLength))
        {
            using var bodyBufferScope = await BufferBodyAsync(context, MAX_BODY_SIZE);
            var bodyBuffer = GetBodyBuffer(context);

            if (IsVerified(publicKey, signatureBuffer, timestampBuffer[..timestampLength], bodyBuffer))
            {
                await next();
                return;
            }
        }

        response.Headers.Clear();
        response.StatusCode = 401;
        await response.CompleteAsync();
        return;
    }

    await next();
}

// Check if the request is an interaction
// This checks if the method is POST and the path is /interactions
static bool IsInteraction(HttpRequest request) =>
        request.Method == "POST" &&
        request.Path.Value == "/interactions";

// Get the signature from the request header to use in the verification
// Check if the request headers are there and the length of the signature is even
// Then decodes the hex signature string and decodes the timestamp string and writes theme to the passed in memory
// the length of the signature is always SIGNATURE_LENGTH 512 bit long and the timestamp length will increase to the end of times
static bool TryGetSignature(HttpRequest request, Memory<byte> signature, Memory<byte> timestamp, out int timestampLength)
{
    var headers = request.Headers;

    if (
        headers.TryGetValue("X-Signature-Ed25519", out var signatureHeader) &&
        signatureHeader.Count == 1 &&
        ((signatureHeader[0]!.Length & 1) == 0) &&
        headers.TryGetValue("X-Signature-Timestamp", out var timestampHeader) &&
        timestampHeader.Count == 1
    )
    {
        _ = HexConverter.TryDecodeFromUtf16(signatureHeader[0]!, signature.Span, out _);
        timestampLength = Encoding.UTF8.GetBytes(timestampHeader[0]!, timestamp.Span);
        return true;
    }

    timestampLength = 0;
    return false;
}

// Rent some memory to write the request body to, so the body can be read multiple times
// This rents at least as much memory as max_body_size, and saves the rented memory to the context
// Then it writes the request body to the rented memory and saves the body content length to the context
// the rented memory should get disposed when the context is no longer in use
static async Task<IDisposable> BufferBodyAsync(HttpContext context, int max_body_size)
{
    var bodyBufferSpan = MemoryPool<byte>.Shared.Rent(max_body_size);
    context.Items[BODY_BUFFER_KEY] = bodyBufferSpan;

    var length = await context.Request.Body.ReadAsync(bodyBufferSpan.Memory[..max_body_size]);
    context.Items[BODY_BUFFER_LENGTH_KEY] = length;

    return bodyBufferSpan;
}

// Get the memory containing the body of the request
// This gets you some of the rented memory stored in the context
static Memory<byte> GetBodyBuffer(HttpContext context)
{
    var bodyBuffer = (IMemoryOwner<byte>)context.Items[BODY_BUFFER_KEY]!;
    var length = (int)context.Items[BODY_BUFFER_LENGTH_KEY]!;

    return bodyBuffer.Memory[..length];
}

// Verify if the signature is legit
// To verify is the signature is correct, the public key, timestamp + body, and signature is needed
static bool IsVerified(PublicKey public_key, Memory<byte> signature, Memory<byte> timestamp, Memory<byte> bodyBuffer)
{
    using var bufferSpan = MemoryPool<byte>.Shared.Rent(timestamp.Length + bodyBuffer.Length);
    var bufferMemory = bufferSpan.Memory[..(timestamp.Length + bodyBuffer.Length)];
    timestamp.CopyTo(bufferMemory);
    bodyBuffer.CopyTo(bufferMemory[timestamp.Length..]);

    return SignatureAlgorithm.Ed25519.Verify(public_key, bufferMemory.Span, signature.Span);
}

static IResult GetRawJsonResult(string json) => Results.Content(json, MediaTypeNames.Application.Json, Encoding.UTF8);
