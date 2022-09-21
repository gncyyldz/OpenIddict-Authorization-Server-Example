using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.AuthorizationServer.ViewModels;
using System.Security.Claims;

namespace OpenIddict.AuthorizationServer.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        public IActionResult Login(string returnUrl)
        {
            TempData["returnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginVM model)
        {
            if (ModelState.IsValid)
            {
                List<Claim> claims = new() { new(ClaimTypes.Name, model.Username) };
                ClaimsIdentity identity = new(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                ClaimsPrincipal principal = new(identity);
                await HttpContext.SignInAsync(principal);

                if (Url.IsLocalUrl(TempData["returnUrl"]?.ToString()))
                    return Redirect(TempData["returnUrl"].ToString());

                return RedirectToAction("Index", "Home");
            }

            return View(model);
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}
