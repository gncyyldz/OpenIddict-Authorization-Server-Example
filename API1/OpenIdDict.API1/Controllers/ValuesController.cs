using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace OpenIdDict.API1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        [HttpGet("[action]")]
        [Authorize("APolicy")]
        public IActionResult A()
        {
            return Ok("Merhaba A");
        }

        [HttpGet("[action]")]
        [Authorize("BPolicy")]
        public IActionResult B()
        {
            return Ok();
        }

        [HttpGet("[action]")]
        [Authorize("CPolicy")]
        public IActionResult C()
        {
            return Ok();
        }

        [HttpGet("[action]")]
        [Authorize("DPolicy")]
        public IActionResult D()
        {
            return Ok();
        }
    }
}
