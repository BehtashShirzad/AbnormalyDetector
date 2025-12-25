using API.Gateway;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using Yarp.ReverseProxy.Configuration;
using static IdentityModel.ClaimComparer;

var builder = WebApplication.CreateBuilder(args);

 
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSingleton<IConnection>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();

    var host = config["RabbitMq:HostName"] ?? "localhost";
    var port = int.Parse(config["RabbitMq:Port"] ?? "5672");
    var user = config["RabbitMq:UserName"] ?? "guest";
    var pass = config["RabbitMq:Password"] ?? "guest";

    var factory = new ConnectionFactory
    {
        HostName = host,
        UserName = user,
        Password = pass,
        Port = port,
    };
    Thread.Sleep(10000);
    return factory.CreateConnectionAsync().GetAwaiter().GetResult();
});

builder.Services.AddSingleton<RabbitMqClient>();
builder.Services.AddMemoryCache();
builder.Services.AddControllers();
// YARP - Load from appsettings.json
builder.Services
    .AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();
app.UseForwardedHeaders();
app.UseMiddleware<RequestProcessorMiddleware>();
// Middleware
app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

// Map YARP
app.MapReverseProxy();
app.MapControllers();
app.Run();
