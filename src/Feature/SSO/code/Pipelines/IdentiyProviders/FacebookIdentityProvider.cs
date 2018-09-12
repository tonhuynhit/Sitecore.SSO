using Microsoft.Owin;
using Microsoft.Owin.Security.Facebook;
using Owin;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Extensions;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using System.Threading.Tasks;

namespace Sitecore.Feature.SSO.Pipelines.IdentiyProviders
{
    public class FacebookIdentityProvider : IdentityProvidersProcessor
    {
        protected override string IdentityProviderName => "Facebook";
        protected IdentityProvider IdentityProvider { get; set; }

        public FacebookIdentityProvider(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider = this.GetIdentityProvider();
            var provider = new FacebookAuthenticationProvider
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

            FacebookAuthenticationOptions fbAuthOptions = new FacebookAuthenticationOptions
            {
                AppId = Configuration.Settings.GetSetting("FedAuth.Facebook.AppId"),
                AppSecret = Configuration.Settings.GetSetting("FedAuth.Facebook.AppSecret"),
                Provider = provider,
                CallbackPath = new PathString("/signin-facebook"),
                AuthenticationType = IdentityProvider.Name
            };

            fbAuthOptions.Scope.Add("email");
            fbAuthOptions.Fields.Add("name");
            fbAuthOptions.Fields.Add("email");
            args.App.UseFacebookAuthentication(fbAuthOptions);
        }
    }
}