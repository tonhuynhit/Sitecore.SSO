using Microsoft.Owin;
using Microsoft.Owin.Security.Google;
using Owin;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Extensions;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using System.Threading.Tasks;

namespace Sitecore.Feature.SSO.Pipelines.IdentiyProviders
{
    public class GoogleIdentityProvider : IdentityProvidersProcessor
    {
        protected override string IdentityProviderName => "Google";
        protected IdentityProvider IdentityProvider { get; set; }

        public GoogleIdentityProvider(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider = this.GetIdentityProvider();

            var provider = new GoogleOAuth2AuthenticationProvider
            {
                OnAuthenticated = (context) =>
                {
                    context.Identity.ApplyClaimsTransformations(new Owin.Authentication.Services.TransformationContext(this.FederatedAuthenticationConfiguration, IdentityProvider));
                    return Task.CompletedTask;
                }
            };

            GoogleOAuth2AuthenticationOptions googleOptions = new GoogleOAuth2AuthenticationOptions
            {
                ClientId = Configuration.Settings.GetSetting("FedAuth.Google.ClientId"),
                ClientSecret = Configuration.Settings.GetSetting("FedAuth.Google.ClientSecret"),
                Provider = provider,
                AuthenticationType = IdentityProvider.Name,
                CallbackPath = new PathString("/signin-google")
            };
            args.App.UseGoogleAuthentication(googleOptions);
        }
    }
}