using Consul;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var servicePort = Convert.ToInt16(builder.Configuration["SERVICE_PORT"].ToString());
var serviceAddress = builder.Configuration["SERVICE_ADDRESS"].ToString();
var serviceScheme = "http";
var serviceUrl = $"{serviceScheme}://0.0.0.0:{servicePort}";
builder.WebHost.UseUrls(serviceUrl);
var app = builder.Build();
using (var client = new ConsulClient(cfg =>
{
    var consulAdress = builder.Configuration["CONSUL_HTTP_ADDR"];
    if (string.IsNullOrWhiteSpace(consulAdress))
        throw new ArgumentNullException(nameof(consulAdress));
    cfg.Address = new Uri(consulAdress);
}))
{
    var registration = new AgentServiceRegistration()
    {
        ID = $"anomaly-service2-{Guid.NewGuid()}", // برای تمایز instanceها
        Name = "anomaly-service3",
        Address = serviceAddress,
        Port = servicePort,
        Check = new AgentServiceCheck()
        {
            HTTP = $"{serviceScheme}://{serviceAddress}:{servicePort}/health",
            Interval = TimeSpan.FromSeconds(10),
            Timeout = TimeSpan.FromSeconds(5),
            TLSSkipVerify = true,
            DeregisterCriticalServiceAfter = TimeSpan.FromSeconds(10)
        }
    };

    await client.Agent.ServiceRegister(registration);
}
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}


app.MapGet("/health", () =>
{
    return Results.Ok("Healthy");
});
app.Run();

 
