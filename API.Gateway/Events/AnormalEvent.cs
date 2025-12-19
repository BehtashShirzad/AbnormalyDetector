namespace API.Gateway.Events
{
    public record AnormalEvent(string ServiceName , string Ip,string Description,Severity Severity, DateTime OccurredAt,object request=null);
  
    public enum Severity
    {
        Info=0,
        Warning=1,
        Error=2,
        Attack=3
    }
}
