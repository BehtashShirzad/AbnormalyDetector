using API.Gateway.Events;
using RabbitMQ.Client;
using System.Data.Common;
using System.Text;
using System.Text.Json;

namespace API.Gateway;
    public class RabbitMqClient(IConfiguration configuration,IConnection connection)
    {
        private readonly IConfiguration _configuration=configuration;
        private readonly IConnection  _connection = connection;

 


    public async Task RaiseEvent(AnormalEvent @event)
    {
        using var channel =await _connection.CreateChannelAsync();

        var exchangeName = _configuration["RabbitMq:ExchangeName"];
        var routingKey = _configuration["RabbitMq:RoutingKey"];

      await  channel.ExchangeDeclareAsync(
            exchange: exchangeName,
            type: ExchangeType.Direct,
            durable: true);

        var body = Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(@event));

     await   channel.BasicPublishAsync(
            exchange: exchangeName,
            routingKey: routingKey,
            body: body);

   
    }

}

 