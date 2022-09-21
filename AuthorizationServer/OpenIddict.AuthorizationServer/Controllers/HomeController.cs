using Microsoft.AspNetCore.Mvc;

namespace OpenIddict.AuthorizationServer.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
