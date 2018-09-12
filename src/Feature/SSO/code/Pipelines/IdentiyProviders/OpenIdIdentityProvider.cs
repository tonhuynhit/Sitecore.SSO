using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Sitecore.Diagnostics;
using Sitecore.Owin.Authentication.Configuration;
using Sitecore.Owin.Authentication.Extensions;
using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
using Sitecore.Owin.Authentication.Services;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Sitecore.Feature.SSO.Pipelines.IdentiyProviders
{
    public class OpenIdIdentityProvider : IdentityProvidersProcessor
    {
        protected override string IdentityProviderName => "OpenId";
        private const string ClientId = "";
        private const string ClientSecret = "";
        private const string Authority = "";
        private const string OauthTokenEndpoint = "/oauth2/v1/token";
        private const string OauthUserInfoEndpoint = "/oauth2/v1/userinfo";
        private const string OauthRedirectUri = "http://habitat.dev.local/identity/externallogincallback";
        private const string OpenIdScope = OpenIdConnectScopes.OpenIdProfile + " email";

        protected IdentityProvider IdentityProvider { get; set; }

        public OpenIdIdentityProvider(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration) : base(federatedAuthenticationConfiguration)
        {
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider = this.GetIdentityProvider();

            var options = new OpenIdConnectAuthenticationOptions
            {
                ClientId = Configuration.Settings.GetSetting("FedAuth.OpenId.ClientId"),
                ClientSecret = Configuration.Settings.GetSetting("FedAuth.OpenId.ClientSecret"),
                Authority = Authority,
                RedirectUri = OauthRedirectUri,
                ResponseType = OpenIdConnectResponseTypes.CodeIdToken,
                Scope = OpenIdScope,
                AuthenticationType = IdentityProvider.Name,
                TokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters
                {
                    NameClaimType = "name"
                },
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = ProcessAuthorizationCodeReceived,
                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                        {
                            var idTokenClaim = n.OwinContext.Authentication.User.FindFirst("id_token");
                            if (idTokenClaim != null)
                            {
                                n.ProtocolMessage.IdTokenHint = idTokenClaim.Value;
                            }
                        }
                        return Task.CompletedTask;
                    }
                }
            };
            args.App.Use(options);
        }

        private async Task ProcessAuthorizationCodeReceived(AuthorizationCodeReceivedNotification notification)
        {
            // Exchange code for access and ID tokens
            var tokenClient = new TokenClient(Authority + OauthTokenEndpoint, ClientId, ClientSecret);
            var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(notification.Code, notification.RedirectUri);
            if (tokenResponse.IsError)
                throw new Exception(tokenResponse.Error);

            var userInfoClient = new UserInfoClient(Authority + OauthUserInfoEndpoint);
            var userInfoResponse = await userInfoClient.GetAsync(tokenResponse.AccessToken);
            var claims = new List<Claim>();
            claims.AddRange(userInfoResponse.Claims);
            claims.Add(new Claim("id_token", tokenResponse.IdentityToken));
            claims.Add(new Claim("access_token", tokenResponse.AccessToken));

            if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
                claims.Add(new Claim("refresh_token", tokenResponse.RefreshToken));

            notification.AuthenticationTicket.Identity.AddClaims(claims);
            notification.AuthenticationTicket.Identity.ApplyClaimsTransformations(new TransformationContext(this.FederatedAuthenticationConfiguration, IdentityProvider));
        }
    }
}