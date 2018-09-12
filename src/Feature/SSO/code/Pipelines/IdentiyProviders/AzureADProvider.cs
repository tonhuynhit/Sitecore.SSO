using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Sitecore.Configuration;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Extensions;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using System.Globalization;
using System.Threading.Tasks;

namespace Sitecore.Feature.SSO.Pipelines.IdentiyProviders
{
    public class AzureADProvider : IdentityProvidersProcessor
    {
        protected override string IdentityProviderName => "AzureAD";
        protected IdentityProvider IdentityProvider { get; set; }

        public AzureADProvider(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, nameof(args));
            IdentityProvider = this.GetIdentityProvider();
            var authenticationType = this.GetAuthenticationType();
            string aadInstance = Settings.GetSetting("FedAuth.AzureID.AADInstance");
            string tenant = Settings.GetSetting("FedAuth.AzureID.Tenant");
            string clientId = Settings.GetSetting("FedAuth.AzureID.ClientId");
            string postLogoutRedirectURI = Settings.GetSetting("edAuth.AzureID.PostLogoutRedirectURI");
            string redirectURI = Settings.GetSetting("edAuth.AzureID.RedirectURI");
            string authority = string.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

            var openIdOption = new OpenIdConnectAuthenticationOptions()
            {
                Caption = IdentityProvider.Caption,
                AuthenticationType = authenticationType,
                AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode.Passive,
                ClientId = clientId,
                Authority = authority,
                PostLogoutRedirectUri = postLogoutRedirectURI,
                RedirectUri = redirectURI,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = (notification) =>
                    {
                        var identity = notification.AuthenticationTicket.Identity;
                        identity.ApplyClaimsTransformations(new Owin.Authentication.Services.TransformationContext(this.FederatedAuthenticationConfiguration, IdentityProvider));
                        notification.AuthenticationTicket = new Microsoft.Owin.Security.AuthenticationTicket(identity, notification.AuthenticationTicket.Properties);
                        return Task.CompletedTask;
                    }
                }
            };

            args.App.UseOpenIdConnectAuthentication(openIdOption);
        }
    }
}