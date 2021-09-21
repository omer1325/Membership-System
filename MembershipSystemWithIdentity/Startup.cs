using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MembershipSystemWithIdentity.CustomValidation;
using MembershipSystemWithIdentity.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace MembershipSystemWithIdentity
{
    public class Startup
    {
        //appsettings'e ulaþmak için bu yöntemi kullanýrýz.
        public IConfiguration configuration { get; }
        public Startup(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers(options => options.EnableEndpointRouting = false);
            services.AddControllersWithViews();

            services.AddDbContext<AppIdentityDbContext>(opts =>
            {
                opts.UseSqlServer(configuration["ConnectionStrings:DefaultConnectionStrings"]);
            });

            services.AddTransient<IAuthorizationHandler, ExpireDateExchangeHandler>();

            //Burada yazdýðýmýz Claim kýsýtlamalarýný ayarlýyoruz.
            services.AddAuthorization(opts => 
            {
                //Kýsýtlamamýzýn ismi "IstanbulPolicy" ve bu ismi hangi controller'a verirsek o contrroller için çalýþacak.
                opts.AddPolicy("IstanbulPolicy", policy =>
                {
                    //Kýsýtlamanýn Tipi "city". Bu tip kenti oluþturduðumuz ClaimProvider içindeki Tip'den gelir.
                    //Ýkinci deðiþken olan Ýstanbul ise Value'dir. Eðer databaseden gelen city deðeri ile bu deðiþken ayný ise sayfaya giriþ yapýlabilir.
                    policy.RequireClaim("city", "Ýstanbul");
                });

                opts.AddPolicy("ViolencePolicy", policy =>
                {
                    policy.RequireClaim("violence");
                });
                opts.AddPolicy("ExchangePolicy", policy =>
                {
                    policy.AddRequirements(new ExpireDateExchangeRequirement());                
                });
            });

            //secrets.json dosyasýndan geliyor
            services.AddAuthentication()
                .AddFacebook(opts =>
                {
                    opts.AppId = configuration["Authentication:Facebook:AppId"];
                    opts.AppSecret = configuration["Authentication:Facebook:AppSecret"];
                })
                .AddGoogle(opts =>
                {
                    opts.ClientId = configuration["Authentication:Google:ClientID"];
                    opts.ClientSecret = configuration["Authentication:Google:ClientSecret"];
                })
                .AddMicrosoftAccount(opts =>
                {
                    opts.ClientId = configuration["Authentication:Microsoft:ClientId"];
                    opts.ClientSecret = configuration["Authentication:Microsoft:ClientSecret"];
                });

            services.AddIdentity<AppUser, AppRole>(opts =>
            {
                opts.User.RequireUniqueEmail = true;
                opts.User.AllowedUserNameCharacters = "abcçdefgðhýijklmnoöpqrsþtuüvwxyzABCÇDEFGÐHIÝJKLMNOÖPQRSÞTUÜVWXYZ0123456789-._";
                opts.Password.RequiredLength = 4;
                opts.Password.RequireNonAlphanumeric = false;
                opts.Password.RequireUppercase = false;
                opts.Password.RequireLowercase = false;
                opts.Password.RequireDigit = false;
            })
                .AddPasswordValidator<CustomPasswordValidator>()
                .AddUserValidator<CustomUserValidator>()
                .AddErrorDescriber<CustomIdentityErrorDescriber>()
                .AddEntityFrameworkStores<AppIdentityDbContext>()
                .AddDefaultTokenProviders();

            CookieBuilder cookieBuilder = new CookieBuilder();

            cookieBuilder.Name = "MyBlog";
            //Cookie bilgisini kötü amaçlý kullanýclar okumasýn diye False yapýyoruz.
            cookieBuilder.HttpOnly = false;
            //Eðer proje kritik bilgiler içerseydi örneðin banka bilgileri gibi, bu özleliði Strict yapmamýz lazým. Kötü amaçlý kullanýcýlar Cookie bilgilerini kullanamasýn diye.
            cookieBuilder.SameSite = SameSiteMode.Lax;
            //Always dersen bütün istekler HTTPS den gönderilir. 
            cookieBuilder.SecurePolicy = CookieSecurePolicy.SameAsRequest;


            services.ConfigureApplicationCookie(opts =>
            {
                //Kullanýcý üye olmadan, sadece üyelerin eriþebildiði sayfaya giderse biz onu Login sayfasýna yönlendiriyoruz.
                opts.LoginPath = new PathString("/Home/Login");
                opts.LogoutPath = new PathString("/Member/LogOut");
                opts.Cookie = cookieBuilder;
                opts.SlidingExpiration = true;
                opts.ExpireTimeSpan = TimeSpan.FromDays(60);
                //Eðer üye olan kullanýcý, yetkisi olmayan sayfalara giriþ yapmak isterse aþaðýdaki Path'e yönlendiriyoruz.
                opts.AccessDeniedPath = new PathString("/Member/AccessDenied");
            });

            //Her request isteðinde cookie oluþurken benim class'ýmýnda çalýþmasýnýda istiyorum.
            services.AddScoped<IClaimsTransformation, ClaimProvider.ClaimProvider>();

            services.AddMvc(); 
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {

            // Sayfada hata aldýðýmýzda o hata ile ilgili açýklayýcý bilgiler sunar
            app.UseDeveloperExceptionPage();
            // Boþ content döndüðünde bize hatanýn nerede olduðunu gösteren Status Code'larýný döner
            app.UseStatusCodePages();
            // JS gibi CSS gibi dosyalarýn yüklenebilmesini saðlar
            app.UseStaticFiles();
            // Identity kütüphanesi kullanacaðýmýz için bunu ekledik
            app.UseAuthentication();

            app.UseMvcWithDefaultRoute();

            



            //app.UseRouting();

            //app.UseEndpoints(endpoints =>
            //{
            //    endpoints.MapGet("/", async context =>
            //    {
            //        await context.Response.WriteAsync("Hello World!");
            //    });
            //});
        }
    }
}
