using System;
using System.Collections;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using Debcenter.Models;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Security.OpenIdConnect;

namespace Debcenter
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity =
                        SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                            validateInterval: TimeSpan.FromMinutes(30),
                            regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // Uncomment the following lines to enable logging in with third party login providers
            //app.UseMicrosoftAccountAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //app.UseTwitterAuthentication(
            //   consumerKey: "",
            //   consumerSecret: "");

            //app.UseFacebookAuthentication(
            //   appId: "",
            //   appSecret: "");

            //app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
            //{
            //    ClientId = "",
            //    ClientSecret = ""
            //});
            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                LoginPath = new PathString("/Home/Login"),


            });
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions {
                Authority = "https://identity.fhict.nl",
                ClientId = "i349135-debcenter",
                SignInAsAuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                Notifications = new OpenIdConnectAuthenticationNotifications {
                    AuthenticationFailed = faildMsg => {
                        if (faildMsg.Exception is OpenIdConnectProtocolInvalidNonceException) {
                            if (faildMsg.Exception.Message.Contains("IDX10311")) {
                                faildMsg.SkipToNextMiddleware();
                            }
                        }
                        return Task.FromResult(0);
                    }
                },
                Scope = "openid profile",
                ResponseType = "id_token",
                RedirectUri = "https://debcenter.nl",
                UseTokenLifetime = false
            });
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions() {
                Authority = "https://identity.fhict.nl",
                ClientId = "i349135-debcenter",
                //    ClientSecret = "OKsefd34tergd",
                Caption = "Fontys OpenID",
                // Scope = "openid",
                SignInAsAuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                Notifications = new OpenIdConnectAuthenticationNotifications {
                    AuthenticationFailed = faildMsg => {
                        if (faildMsg.Exception is OpenIdConnectProtocolInvalidNonceException) {
                            if (faildMsg.Exception.Message.Contains("IDX10311")) {
                                faildMsg.SkipToNextMiddleware();
                            }
                        }
                        return Task.FromResult(0);
                    }
                },
                //ProtocolValidator = new OpenIdConnectProtocolValidator() {
                //    RequireNonce = false,
                //},
                ResponseType = "id_token",
                UseTokenLifetime = false,
                RedirectUri = "https://debcenter.nl"
            });
        }
    }
}