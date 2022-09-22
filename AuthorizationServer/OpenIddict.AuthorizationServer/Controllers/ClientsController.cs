using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.AuthorizationServer.ViewModels;

namespace OpenIddict.AuthorizationServer.Controllers
{
    public class ClientsController : Controller
    {
        readonly IOpenIddictApplicationManager _openIddictApplicationManager;

        public ClientsController(IOpenIddictApplicationManager openIddictApplicationManager)
        {
            _openIddictApplicationManager = openIddictApplicationManager;
        }

        [HttpGet]
        public async Task<IActionResult> CreateClient()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> CreateClient(ClientCreateVM model)
        {
            var client = await _openIddictApplicationManager.FindByClientIdAsync(model.ClientId);
            if (client is null)
            {
                await _openIddictApplicationManager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = model.ClientId,
                    ClientSecret = model.ClientSecret,
                    DisplayName = model.DisplayName,
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                        OpenIddictConstants.Permissions.Prefixes.Scope + "read",
                        OpenIddictConstants.Permissions.Prefixes.Scope + "write"
                    }
                });
                ViewBag.Message = "Client başarıyla oluşturulmuştur.";
                return View();
            }
            ViewBag.Message = "Client zaten mevcuttur.";
            return View();
        }
    }
}
