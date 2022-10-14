using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using OpenIddict.AuthorizationServer.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options => options.LoginPath = "/account/login");

//OpenIddict servisini uygulamaya ekliyoruz.
builder.Services.AddOpenIddict()
    //OpenIddict core/çekirdek yapýlandýrmalarý gerçekleþtiriliyor.
    .AddCore(options =>
    {
        //Entity Framework Core kullanýlacaðý bildiriliyor.
        options.UseEntityFrameworkCore()
               //Kullanýlacak context nesnesi bildiriliyor.
               .UseDbContext<ApplicationDbContext>();
    })
    //OpenIddict server yapýlandýrmalarý gerçekleþtiriliyor.
    .AddServer(options =>
    {
        //Token talebinde bulunulacak endpoint'i set ediyoruz.
        options.SetTokenEndpointUris("/connect/token")
               //Authorization Code talebinde bulunulacak endpoint'i set ediyoruz.
               .SetAuthorizationEndpointUris("/connect/authorize")
               //Logout isteði geldiðinde yönlendirilecek endpoint'i set ediyoruz.
               .SetLogoutEndpointUris("/connect/logout");
        //Akýþ türü olarak Client Credentials Flow'u etkinleþtiriyoruz.
        options.AllowClientCredentialsFlow()
               //Authorization Code Flow'u etkileþtiriyoruz.
               .AllowAuthorizationCodeFlow()
               .RequireProofKeyForCodeExchange();
        //Signing ve encryption sertifikalarýný ekliyoruz.
        options.AddEphemeralEncryptionKey()
               .AddEphemeralSigningKey()
               //Normalde OpenIddict üretilecek token'ý güvenlik amacýyla þifreli bir þekilde bizlere sunmaktadýr.
               //Haliyle jwt.io sayfasýnda bu token'ý çözümleyip görmek istediðimizde þifresinden dolayý
               //incelemede bulunamayýz. Bu DisableAccessTokenEncryption özelliði sayesinde üretilen access token'ýn
               //þifrelenmesini iptal ediyoruz.
               .DisableAccessTokenEncryption();
        //OpenIddict Server servislerini IoC Container'a ekliyoruz.
        options.UseAspNetCore()
               //EnableTokenEndpointPassthrough : OpenID Connect request'lerinin OpenIddict tarafýndan iþlenmesi için gerekli konfigürasyonu saðlar.
               .EnableTokenEndpointPassthrough()
               //EnableAuthorizationEndpointPassthrough: OpenID Connect request'lerinin Authorization Endpoint için aktifleþtirilmesini saðlar.
               .EnableAuthorizationEndpointPassthrough()
               .EnableLogoutEndpointPassthrough();
        //Yetkileri(scope) belirliyoruz.
        options.RegisterScopes("read", "write");
    });

//OpenIddict'i SQL Server'ý kullanacak þekilde yapýlandýrýyoruz.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("SQLServer"));
    //OpenIddict tarafýndan ihtiyaç duyulan Entity sýnýflarýný kaydediyoruz.
    options.UseOpenIddict();
});

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
