using Microsoft.AspNetCore.Mvc;

namespace API.Gateway.Controller
{
    public class TestController : ControllerBase
    {
        [HttpGet("api/test/{testParam}")]
        public async Task Test([FromRoute] string testParam, [FromQuery]string test)
        {
            await Task.CompletedTask;
        }
    }
}
