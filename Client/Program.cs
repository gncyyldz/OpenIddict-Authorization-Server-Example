using Client.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("SQLServer"));
    options.UseOpenIddict();
});

builder.Services.AddAuthentication(options => options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/login";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(15);
    });

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
        .UseDbContext<ApplicationDbContext>();

        //Burada MongoDB kullanmak isterseniz aþaðýdaki yapýlandýrma kodlarýndan istifade edebilirsiniz.
        // options.UseMongoDb()
        //        .UseDatabase(new MongoClient().GetDatabase("openiddict"));
    })
    //OpenIddict client componentinin yapýlandýrmasý.
    .AddClient(options =>
    {
        options.SetRedirectionEndpointUris("/callback/login/local");
        options.SetPostLogoutRedirectionEndpointUris("/callback/logout/local");

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
                      .EnableStatusCodePagesIntegration()
                      .EnableRedirectionEndpointPassthrough()
                      .EnablePostLogoutRedirectionEndpointPassthrough();

        options.UseSystemNetHttp();

        options.AddRegistration(new OpenIddictClientRegistration
        {
            Issuer = new Uri("https://localhost:7047", UriKind.Absolute),

            ClientId = "my-client",
            ClientSecret = "my-client-secret",
            Scopes = { "read", "write" },

            RedirectUri = new Uri("https://localhost:7226/callback/login/local", UriKind.Absolute),
            PostLogoutRedirectUri = new Uri("https://localhost:7226/callback/logout/local", UriKind.Absolute),
        });
    });

builder.Services.AddHttpClient();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
