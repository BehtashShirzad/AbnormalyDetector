using API.Gateway;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using Yarp.ReverseProxy.Configuration;
using static IdentityModel.ClaimComparer;

var builder = WebApplication.CreateBuilder(args);

// Swagger
builder.Services.Configure<APIGatewayOptions>(builder.Configuration);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<IConnection>(sp =>
{
    var opt = sp.GetRequiredService<IOptions<APIGatewayOptions>>();

    var factory = new ConnectionFactory
    {
        HostName = opt.Value.Rabbitmq.HostName,
        UserName = opt.Value.Rabbitmq.UserName,
        Password = opt.Value.Rabbitmq.Password,
        Port = opt.Value.Rabbitmq.Port,
    };

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
app.UseMiddleware<RequestProcessorMiddleware>();
// Middleware
app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

// Map YARP
app.MapReverseProxy();
app.MapControllers();
app.Run();
