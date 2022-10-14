using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client.AspNetCore;

namespace Client.Controllers
{
    public class HomeController : Controller
    {
        readonly IHttpClientFactory _httpClientFactory;

        public HomeController(IHttpClientFactory httpClientFactory)
            => _httpClientFactory = httpClientFactory;

        public IActionResult Index()
            => View();

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> Index(CancellationToken cancellationToken)
        {
            string? token = await HttpContext.GetTokenAsync(CookieAuthenticationDefaults.AuthenticationScheme, OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken);

            using HttpClient httpClient = _httpClientFactory.CreateClient();
            using HttpRequestMessage httpRequestMessage = new(HttpMethod.Get, "https://localhost:7056/api/values/a");
            httpRequestMessage.Headers.Authorization = new("Bearer", token);

            using HttpResponseMessage httpResponseMessage = await httpClient.SendAsync(httpRequestMessage, cancellationToken);

            return View(model: await httpResponseMessage.Content.ReadAsStringAsync(cancellationToken));
        }
    }
}
