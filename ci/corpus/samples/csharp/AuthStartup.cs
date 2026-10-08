using System;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace MyGuard.Samples
{
    public class AuthStartup
    {
        private readonly IConfiguration configuration;

        public AuthStartup(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        public TokenValidationParameters ValidationParameters()
        {
            var key = Encoding.UTF8.GetBytes(configuration["Jwt:Key"]);
            return new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = configuration["Jwt:Issuer"],
                ValidateLifetime = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
            };
        }

        public string ConnectionString()
        {
            var builder = new SqlConnectionStringBuilder(configuration.GetConnectionString("Default"));
            builder.Password = configuration["Db:Password"];
            return builder.ConnectionString;
        }

        public NetworkCredential ProxyCredential()
        {
            return new NetworkCredential(configuration["Proxy:User"], configuration["Proxy:Password"]);
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }

            app.UseCookiePolicy(new CookiePolicyOptions
            {
                HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.Always,
                Secure = CookieSecurePolicy.Always,
            });
        }

        public static string SetPreference(HttpResponse response, string value)
        {
            response.Cookies.Append("theme", value, new CookieOptions { HttpOnly = false, Secure = true });
            return value;
        }

        public static NetworkCredential LegacyCredential()
        {
            return new NetworkCredential("svc-backup", "Winter2024!");
        }
    }
}
