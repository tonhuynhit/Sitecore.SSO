using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Auth0.Owin;
using Sitecore.Owin.Authentication.Extensions;
using System.Threading.Tasks;
using Owin;
using Microsoft.Owin;

namespace Sitecore.Feature.SSO.Pipelines.IdentiyProviders
{
    public class Auth0IdentityProvider : IdentityProvidersProcessor
    {
        protected override string IdentityProviderName => "Auth0";
        protected IdentityProvider IdentityProvider { get; set; }

        public Auth0IdentityProvider(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, nameof(args));
            IdentityProvider = this.GetIdentityProvider();
            var provider = new Auth0AuthenticationProvider
            {
                OnAuthenticated = (context) =>
                {
                    context.Identity.ApplyClaimsTransformations(new Owin.Authentication.Services.TransformationContext(this.FederatedAuthenticationConfiguration, IdentityProvider));
                    return Task.CompletedTask;
                },
                OnReturnEndpoint = (context) =>
                {
                    return Task.CompletedTask;
                }
            };
            var auth0options = new Auth0AuthenticationOptions
            {
                ClientId = Configuration.Settings.GetSetting("FedAuth.Auth0.ClientId"),
                ClientSecret = Configuration.Settings.GetSetting("FedAuth.Auth0.ClientSecret"),
                Provider = provider,
                Domain = Configuration.Settings.GetSetting("FedAuth.Auth0.Domain"),
                AuthenticationType = IdentityProvider.Name,
                CallbackPath = new PathString("/signin-auth0"),
            };
            args.App.UseAuth0Authentication(auth0options);
        }
    }
}