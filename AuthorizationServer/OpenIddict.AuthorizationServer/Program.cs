using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using OpenIddict.AuthorizationServer.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options => options.LoginPath = "/account/login");

//OpenIddict servisini uygulamaya ekliyoruz.
builder.Services.AddOpenIddict()
    //OpenIddict core/�ekirdek yap�land�rmalar� ger�ekle�tiriliyor.
    .AddCore(options =>
    {
        //Entity Framework Core kullan�laca�� bildiriliyor.
        options.UseEntityFrameworkCore()
               //Kullan�lacak context nesnesi bildiriliyor.
               .UseDbContext<ApplicationDbContext>();
    })
    //OpenIddict server yap�land�rmalar� ger�ekle�tiriliyor.
    .AddServer(options =>
    {
        //Token talebinde bulunulacak endpoint'i set ediyoruz.
        options.SetTokenEndpointUris("/connect/token")
               //Authorization Code talebinde bulunulacak endpoint'i set ediyoruz.
               .SetAuthorizationEndpointUris("/connect/authorize")
               //Logout iste�i geldi�inde y�nlendirilecek endpoint'i set ediyoruz.
               .SetLogoutEndpointUris("/connect/logout");
        //Ak�� t�r� olarak Client Credentials Flow'u etkinle�tiriyoruz.
        options.AllowClientCredentialsFlow()
               //Authorization Code Flow'u etkile�tiriyoruz.
               .AllowAuthorizationCodeFlow()
               .RequireProofKeyForCodeExchange();
        //Signing ve encryption sertifikalar�n� ekliyoruz.
        options.AddEphemeralEncryptionKey()
               .AddEphemeralSigningKey()
               //Normalde OpenIddict �retilecek token'� g�venlik amac�yla �ifreli bir �ekilde bizlere sunmaktad�r.
               //Haliyle jwt.io sayfas�nda bu token'� ��z�mleyip g�rmek istedi�imizde �ifresinden dolay�
               //incelemede bulunamay�z. Bu DisableAccessTokenEncryption �zelli�i sayesinde �retilen access token'�n
               //�ifrelenmesini iptal ediyoruz.
               .DisableAccessTokenEncryption();
        //OpenIddict Server servislerini IoC Container'a ekliyoruz.
        options.UseAspNetCore()
               //EnableTokenEndpointPassthrough : OpenID Connect request'lerinin OpenIddict taraf�ndan i�lenmesi i�in gerekli konfig�rasyonu sa�lar.
               .EnableTokenEndpointPassthrough()
               //EnableAuthorizationEndpointPassthrough: OpenID Connect request'lerinin Authorization Endpoint i�in aktifle�tirilmesini sa�lar.
               .EnableAuthorizationEndpointPassthrough()
               .EnableLogoutEndpointPassthrough();
        //Yetkileri(scope) belirliyoruz.
        options.RegisterScopes("read", "write");
    });

//OpenIddict'i SQL Server'� kullanacak �ekilde yap�land�r�yoruz.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("SQLServer"));
    //OpenIddict taraf�ndan ihtiya� duyulan Entity s�n�flar�n� kaydediyoruz.
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
