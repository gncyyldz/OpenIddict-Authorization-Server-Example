using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.AuthorizationServer.Controllers
{
    public class AuthorizationController : Controller
    {
        readonly IOpenIddictApplicationManager _applicationManager;

        public AuthorizationController(IOpenIddictApplicationManager applicationManager)
        {
            _applicationManager = applicationManager;
        }

        //Bu action'ın endpoint'ini token endpoint ile aynı şekilde ayarlıyoruz.
        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest();
            if (request?.IsClientCredentialsGrantType() is not null)
            {
                //Client credentials OpenIddict tarafından otomatik olarak doğrulanır.
                //Eğer ki gelen request'in body'sindeki client_id veya client_secret bilgileri geçersizse, burası tetiklenmeyecektir.

                var application = await _applicationManager.FindByClientIdAsync(request.ClientId);
                if (application is null)
                    throw new InvalidOperationException("This clientId was not found");

                var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                //Token'a claim'leri ekleyelim. Subject'in eklenmesi zorunludur.
                //Destination'lar ile claim'lerin hangi token'a ekleneceğini belirtiyoruz. AccessToken mı? Identity Token mı? Yoksa her ikisi de mi?
                identity.AddClaim(Claims.Subject, (await _applicationManager.GetClientIdAsync(application) ?? throw new InvalidOperationException()), Destinations.AccessToken, Destinations.IdentityToken);
                identity.AddClaim(Claims.Name, (await _applicationManager.GetDisplayNameAsync(application) ?? throw new InvalidOperationException()), Destinations.AccessToken, Destinations.IdentityToken);
                identity.AddClaim("ozel-claim", "ozel-claim-value", Destinations.AccessToken, Destinations.IdentityToken);

                identity.AddClaim(JwtRegisteredClaimNames.Aud, "Example-OpenIddict", Destinations.AccessToken, Destinations.IdentityToken);

                var claimsPrincipal = new ClaimsPrincipal(identity);
                claimsPrincipal.SetScopes(request.GetScopes());

                //SignIn return etmek, biryandan OpenIddict'ten uygun access/identity token talebinde bulunmaktır.
                return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }
            throw new NotImplementedException("The specified grant type is not implemented.");
        }
    }
}
