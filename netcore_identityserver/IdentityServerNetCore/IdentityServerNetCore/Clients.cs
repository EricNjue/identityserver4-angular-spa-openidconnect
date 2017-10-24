using IdentityServer4;
using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServerNetCore
{
    internal class Clients
    {
        public static IEnumerable<Client> Get()
        {
            return new List<Client> {
            new Client {
                ClientId = "oauthClient",
                ClientName = "Example Client Credentials Client Application",
                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets = new List<Secret> {
                    new Secret("superSecretPassword".Sha256())},
                AllowedScopes = new List<string> {"customAPI.read"}
            },
            new Client {
                ClientId = "openIdConnectClient",
                ClientName = "Example Implicit Client Application",
                AllowedGrantTypes = GrantTypes.Implicit,
                AllowedScopes = new List<string>
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    IdentityServerConstants.StandardScopes.Email,
                    "role",
                    "customAPI.write"
                },
                RedirectUris = new List<string> {"https://localhost:44398/signin-oidc"},
                PostLogoutRedirectUris = new List<string> { "https://localhost:44398" }
            },
            new Client {
                ClientId = "angular_spa",
                ClientName = "Angular 4 Client",
                AllowedGrantTypes = GrantTypes.Implicit,
                AllowedScopes = new List<string> { "openid", "profile", "api1" },
                RedirectUris = new List<string> { "http://localhost:4200/auth-callback" },
                PostLogoutRedirectUris = new List<string> { "http://localhost:4200/" },
                AllowedCorsOrigins = new List<string> { "http://localhost:4200" },
                AllowAccessTokensViaBrowser = true
            }
        };
        }
    }
}
