namespace API.Gateway
{
    public class APIGatewayOptions
    {
        public Rabbitmq Rabbitmq { get; set; }
    }
}

 
 
public class Rabbitmq
{
    public string HostName { get; set; }
    public string UserName { get; set; }
    public string Password { get; set; }
    public int Port { get; set; }
    public string ExchangeName { get; set; }
    public string RoutingKey { get; set; }
}
 
 
