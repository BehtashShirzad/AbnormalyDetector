using API.Gateway;
using Consul;
using Yarp.ReverseProxy.Configuration;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<IConsulClient, ConsulClient>(p => new ConsulClient(cfg =>
{
    cfg.Address = new Uri("http://localhost:8500"); // آدرس Consul
}));
builder.Services.AddReverseProxy()
    .LoadFromMemory(new List<Yarp.ReverseProxy.Configuration.RouteConfig>(), new List<ClusterConfig>());
builder.Services.AddHostedService<ConsulYarpUpdater>();
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.MapReverseProxy();

app.Run();
 
