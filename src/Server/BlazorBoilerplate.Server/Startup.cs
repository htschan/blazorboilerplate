using AutoMapper;
using static BlazorBoilerplate.Constants.PasswordPolicy;
using BlazorBoilerplate.Infrastructure.AuthorizationDefinitions;
using BlazorBoilerplate.Infrastructure.Server;
using BlazorBoilerplate.Infrastructure.Storage;
using BlazorBoilerplate.Infrastructure.Storage.DataModels;
using BlazorBoilerplate.Infrastructure.Storage.Permissions;
using BlazorBoilerplate.Server.Authorization;
using BlazorBoilerplate.Server.Extensions;
using BlazorBoilerplate.Server.Factories;
using BlazorBoilerplate.Server.Managers;
using BlazorBoilerplate.Server.Middleware;
using BlazorBoilerplate.Shared.Dto.ExternalAuth;
using BlazorBoilerplate.Shared.Interfaces;
using BlazorBoilerplate.Shared.Localizer;
using BlazorBoilerplate.Shared.Models;
using BlazorBoilerplate.Shared.Providers; //ServerSideBlazor
using BlazorBoilerplate.Shared.Services;
using BlazorBoilerplate.Shared.Validators.Db;
using BlazorBoilerplate.Storage;
using BlazorBoilerplate.Storage.Mapping;
using Breeze.AspNetCore;
using Breeze.Core;
using FluentValidation.AspNetCore;
using IdentityServer4;
using IdentityServer4.AccessTokenValidation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization; //ServerSideBlazor
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json.Serialization;
using NSwag;
using NSwag.AspNetCore;
using NSwag.Generation.Processors.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http; //ServerSideBlazor
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using static IdentityServer4.IdentityServerConstants;
using static Microsoft.AspNetCore.Http.StatusCodes;

namespace BlazorBoilerplate.Server
{
   public class Startup
   {
      public IConfiguration Configuration { get; }

      private readonly IWebHostEnvironment _environment;
      private readonly bool _enableAPIDoc;

      private readonly string projectName = nameof(BlazorBoilerplate);

      public Startup(IConfiguration configuration, IWebHostEnvironment env)
      {
         Configuration = configuration;
         _environment = env;
         _enableAPIDoc = configuration.GetSection("BlazorBoilerplate:Api:Doc:Enabled").Get<bool>();
      }

      public void ConfigureServices(IServiceCollection services)
      {
         services.AddSingleton<ILocalizationProvider, StorageLocalizationProvider>();
         services.AddTextLocalization(options =>
         {
            options.ReturnOnlyKeyIfNotFound = !_environment.IsDevelopment();
            options.FallBackNeutralCulture = !_environment.IsDevelopment();
         }).Configure<RequestLocalizationOptions>(options =>
         {
            options.DefaultRequestCulture = new RequestCulture(Settings.SupportedCultures[0]);
            options.AddSupportedCultures(Settings.SupportedCultures);
            options.AddSupportedUICultures(Settings.SupportedCultures);
         });

         var dataProtectionBuilder = services.AddDataProtection().SetApplicationName(projectName);

         services.RegisterStorage(Configuration);

         services.Configure<ApiBehaviorOptions>(options => { options.SuppressModelStateInvalidFilter = true; });

         services.AddIdentity<ApplicationUser, ApplicationRole>()
             .AddRoles<ApplicationRole>()
             .AddEntityFrameworkStores<ApplicationDbContext>()
             .AddDefaultTokenProviders()
             .AddErrorDescriber<LocalizedIdentityErrorDescriber>();

         services.AddScoped<IUserClaimsPrincipalFactory<ApplicationUser>,
             AdditionalUserClaimsPrincipalFactory>();

         var authAuthority = Configuration[$"{projectName}:IS4ApplicationUrl"].TrimEnd('/');

         // Adds IdentityServer https://identityserver4.readthedocs.io/en/latest/reference/options.html
         var identityServerBuilder = services.AddIdentityServer(options =>
         {
            options.IssuerUri = authAuthority;
            options.Events.RaiseErrorEvents = true;
            options.Events.RaiseInformationEvents = true;
            options.Events.RaiseFailureEvents = true;
            options.Events.RaiseSuccessEvents = true;
            options.UserInteraction.ErrorUrl = "/identityserver/error";
         })
           .AddIdentityServerStores(Configuration)
           .AddAspNetIdentity<ApplicationUser>(); //https://identityserver4.readthedocs.io/en/latest/reference/aspnet_identity.html

         var keysFolder = Path.Combine(_environment.ContentRootPath, "Keys");

         if (_environment.IsDevelopment())
         {
            // The AddDeveloperSigningCredential extension creates temporary key material tempkey.jwk for signing tokens.
            // This might be useful to get started, but needs to be replaced by some persistent key material for production scenarios.
            // See http://docs.identityserver.io/en/release/topics/crypto.html#refcrypto for more information.
            // https://stackoverflow.com/questions/42351274/identityserver4-hosting-in-iis

            identityServerBuilder.AddDeveloperSigningCredential();

            dataProtectionBuilder.PersistKeysToFileSystem(new DirectoryInfo(keysFolder));
         }
         else
         {
            dataProtectionBuilder.PersistKeysToFileSystem(new DirectoryInfo(keysFolder));
         }

         var authBuilder = services.AddAuthentication(options =>
         {
            options.DefaultScheme = IdentityServerAuthenticationDefaults.AuthenticationScheme;
         })
         .AddIdentityServerAuthentication(options =>
         {
            options.Authority = authAuthority;
            options.SupportedTokens = SupportedTokens.Jwt;
            options.RequireHttpsMetadata = _environment.IsProduction();
            options.ApiName = IdentityServerConfig.LocalApiName;
            options.Events = new JwtBearerEvents
            {
               OnMessageReceived = context =>
                  {
                     var accessToken = context.Request.Query["access_token"];

                     // If the request is for our hub...
                     var path = context.HttpContext.Request.Path;
                     if (!string.IsNullOrEmpty(accessToken) &&
                            (path.StartsWithSegments("/chathub")))
                     {
                        // Read the token out of the query string
                        context.Token = accessToken;
                     }
                     return Task.CompletedTask;
                  }
            };
         });

         #region ExternalAuthProviders
         //https://github.com/dotnet/aspnetcore/blob/master/src/Security/Authentication/samples/SocialSample/Startup.cs
         //https://docs.microsoft.com/en-us/aspnet/core/security/authentication/social/google-logins
         if (Convert.ToBoolean(Configuration["ExternalAuthProviders:Google:Enabled"] ?? "false"))
         {
            authBuilder.AddGoogle(options =>
            {
               options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

               options.ClientId = Configuration["ExternalAuthProviders:Google:ClientId"];
               options.ClientSecret = Configuration["ExternalAuthProviders:Google:ClientSecret"];

               options.AuthorizationEndpoint += "?prompt=consent"; // Hack so we always get a refresh token, it only comes on the first authorization response
               options.AccessType = "offline";
               options.SaveTokens = true;
               options.Events = new OAuthEvents()
               {
                  OnRemoteFailure = HandleOnRemoteFailure
               };
               options.ClaimActions.MapJsonSubKey("urn:google:image", "image", "url");
               options.ClaimActions.Remove(ClaimTypes.GivenName);
            });
         }

         if (Convert.ToBoolean(Configuration["ExternalAuthProviders:Facebook:Enabled"] ?? "false"))
         {
            // You must first create an app with Facebook and add its ID and Secret to your user-secrets.
            // https://developers.facebook.com/apps/
            // https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#login
            authBuilder.AddFacebook(options =>
            {
               options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

               options.AppId = Configuration["ExternalAuthProviders:Facebook:AppId"];
               options.AppSecret = Configuration["ExternalAuthProviders:Facebook:AppSecret"];

               options.Scope.Add("email");
               options.Fields.Add("name");
               options.Fields.Add("email");
               options.SaveTokens = true;
               options.Events = new OAuthEvents()
               {
                  OnRemoteFailure = HandleOnRemoteFailure
               };
            });
         }

         #endregion

         #region Authorization
         //Add Policies / Claims / Authorization - https://identityserver4.readthedocs.io/en/latest/topics/add_apis.html#advanced 
         services.AddScoped<EntityPermissions>();
         services.AddSingleton<IAuthorizationPolicyProvider, AuthorizationPolicyProvider>();
         services.AddTransient<IAuthorizationHandler, DomainRequirementHandler>();
         services.AddTransient<IAuthorizationHandler, PermissionRequirementHandler>();
         #endregion

         services.Configure<IdentityOptions>(options =>
         {
            // Password settings
            options.Password.RequireDigit = RequireDigit;
            options.Password.RequiredLength = RequiredLength;
            options.Password.RequireNonAlphanumeric = RequireNonAlphanumeric;
            options.Password.RequireUppercase = RequireUppercase;
            options.Password.RequireLowercase = RequireLowercase;
            //options.Password.RequiredUniqueChars = 6;

            // Lockout settings
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
            options.Lockout.MaxFailedAccessAttempts = 10;
            options.Lockout.AllowedForNewUsers = true;

            // Require Confirmed Email User settings
            if (Convert.ToBoolean(Configuration[$"{projectName}:RequireConfirmedEmail"] ?? "false"))
            {
               options.User.RequireUniqueEmail = true;
               options.SignIn.RequireConfirmedEmail = true;
            }
         });

         #region Cookies
         // cookie policy to deal with temporary browser incompatibilities
         services.AddSameSiteCookiePolicy();

         //https://docs.microsoft.com/en-us/aspnet/core/security/gdpr
         services.Configure<CookiePolicyOptions>(options =>
         {
            // This lambda determines whether user consent for non-essential
            // cookies is needed for a given request.
            options.CheckConsentNeeded = context => false; //consent not required
                                                           // requires using Microsoft.AspNetCore.Http;
                                                           //options.MinimumSameSitePolicy = SameSiteMode.None;
         });

         //services.ConfigureExternalCookie(options =>
         // {
         // macOS login fix
         //options.Cookie.SameSite = SameSiteMode.None;
         //});

         services.ConfigureApplicationCookie(options =>
         {
            options.Cookie.IsEssential = true;
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
            options.LoginPath = Constants.Settings.LoginPath;
            //options.AccessDeniedPath = "/Identity/Account/AccessDenied";
            // ReturnUrlParameter requires
            //using Microsoft.AspNetCore.Authentication.Cookies;
            options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;
            options.SlidingExpiration = true;

            // Suppress redirect on API URLs in ASP.NET Core -> https://stackoverflow.com/a/56384729/54159
            options.Events = new CookieAuthenticationEvents()
            {
               OnRedirectToAccessDenied = context =>
                  {
                     if (context.Request.Path.StartsWithSegments("/api"))
                     {
                        context.Response.StatusCode = Status403Forbidden;
                     }

                     return Task.CompletedTask;
                  },
               OnRedirectToLogin = context =>
                  {
                     context.Response.StatusCode = Status401Unauthorized;
                     return Task.CompletedTask;
                  }
            };
         });
         #endregion

         services.AddMvc().AddNewtonsoftJson(opt =>
         {
            // Set Breeze defaults for entity serialization
            var ss = JsonSerializationFns.UpdateWithDefaults(opt.SerializerSettings);
            if (ss.ContractResolver is DefaultContractResolver resolver)
            {
               resolver.NamingStrategy = null;  // remove json camelCasing; names are converted on the client.
            }
            if (_environment.IsDevelopment())
            {
               ss.Formatting = Newtonsoft.Json.Formatting.Indented; // format JSON for debugging
            }
         })   // Add Breeze exception filter to send errors back to the client
         .AddMvcOptions(o => { o.Filters.Add(new GlobalExceptionFilter()); })
         .AddViewLocalization().AddDataAnnotationsLocalization(options =>
         {
            options.DataAnnotationLocalizerProvider = (type, factory) =>
               {
                  return factory.Create(typeof(Global));
               };
         }).AddFluentValidation(fv => fv.RegisterValidatorsFromAssemblyContaining<LocalizationRecordValidator>());

         services.AddServerSideBlazor().AddCircuitOptions(o =>
         {
            if (_environment.IsDevelopment())
            {
               o.DetailedErrors = true;
            }
         }).AddHubOptions(o =>
         {
            o.MaximumReceiveMessageSize = 131072;
         });

         services.AddSignalR();

         if (_enableAPIDoc)
            services.AddOpenApiDocument(document =>
            {
               document.Title = "BlazorBoilerplate API";
               document.Version = typeof(Startup).GetTypeInfo().Assembly.GetName().Version.ToString();
               document.AddSecurity("bearer", Enumerable.Empty<string>(), new OpenApiSecurityScheme
               {
                  Type = OpenApiSecuritySchemeType.OAuth2,
                  Description = "Local Identity Server",
                  OpenIdConnectUrl = $"{authAuthority}/.well-known/openid-configuration", //not working
                  Flow = OpenApiOAuth2Flow.AccessCode,
                  Flows = new OpenApiOAuthFlows()
                  {
                     AuthorizationCode = new OpenApiOAuthFlow()
                     {
                        Scopes = new Dictionary<string, string>
                            {
                                { LocalApi.ScopeName, IdentityServerConfig.LocalApiName }
                            },
                        AuthorizationUrl = $"{authAuthority}/connect/authorize",
                        TokenUrl = $"{authAuthority}/connect/token"
                     },
                  }
               }); ;

               document.OperationProcessors.Add(new AspNetCoreOperationSecurityScopeProcessor("bearer"));
               //      new OperationSecurityScopeProcessor("bearer"));
            });

         services.AddScoped<IUserSession, UserSession>();

         services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

         services.Add(ServiceDescriptor.Scoped(typeof(ITenantSettings<>), typeof(TenantSettingsManager<>)));

         services.AddTransient<IEmailFactory, EmailFactory>();

         services.AddTransient<IAccountManager, AccountManager>();
         services.AddTransient<IAdminManager, AdminManager>();
         services.AddTransient<IEmailManager, EmailManager>();
         services.AddTransient<IExternalAuthManager, ExternalAuthManager>();

         #region Automapper
         //Automapper to map DTO to Models https://www.c-sharpcorner.com/UploadFile/1492b1/crud-operations-using-automapper-in-mvc-application/
         var automapperConfig = new MapperConfiguration(configuration =>
         {
            configuration.AddProfile(new MappingProfile());
         });

         var autoMapper = automapperConfig.CreateMapper();

         services.AddSingleton(autoMapper);
         #endregion

         /* ServerSideBlazor */
         services.AddScoped<IAccountApiClient, AccountApiClient>();
         services.AddScoped<AppState>();

         // setup HttpClient for server side in a client side compatible fashion ( with auth cookie )
         // if (!services.Any(x => x.ServiceType == typeof(HttpClient)))
         // {
         services.AddScoped(s =>
         {
            // creating the URI helper needs to wait until the JS Runtime is initialized, so defer it.
            var navigationManager = s.GetRequiredService<NavigationManager>();
            var httpContextAccessor = s.GetRequiredService<IHttpContextAccessor>();
            var cookies = httpContextAccessor.HttpContext.Request.Cookies;
            var httpClientHandler = new HttpClientHandler() { UseCookies = false };
            if (_environment.IsDevelopment())
            {
               // Return 'true' to allow certificates that are untrusted/invalid
               httpClientHandler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => { return true; };
            }
            var client = new HttpClient(httpClientHandler);
            if (cookies.Any())
            {
               var cks = new List<string>();

               foreach (var cookie in cookies)
               {
                  cks.Add($"{cookie.Key}={cookie.Value}");
               }

               client.DefaultRequestHeaders.Add("Cookie", string.Join(';', cks));
            }

            client.BaseAddress = new Uri(navigationManager.BaseUri);

            return client;
         });
         // }

         services.AddScoped<ILocalizationApiClient, LocalizationApiClient>();
         services.AddScoped<IApiClient, ApiClient>();

         // Authentication providers
         var serviceDescriptor = services.FirstOrDefault(descriptor => descriptor.ServiceType == typeof(AuthenticationStateProvider));
         if (serviceDescriptor != null)
         {
            services.Remove(serviceDescriptor);
         }

         services.AddScoped<AuthenticationStateProvider, IdentityAuthenticationStateProvider>();
         /**********************/

         services.AddModules();
      }

      // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
      public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
      {
         app.UseRequestLocalization();

         // cookie policy to deal with temporary browser incompatibilities
         app.UseCookiePolicy();

         if (env.IsDevelopment())
         {
            app.UseDeveloperExceptionPage();
            app.UseWebAssemblyDebugging(); //ClientSideBlazor
         }
         else
         {
            app.UseHttpsRedirection();
            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            //    app.UseHsts(); //HSTS Middleware (UseHsts) to send HTTP Strict Transport Security Protocol (HSTS) headers to clients.
         }

         app.UseStaticFiles();
         app.UseBlazorFrameworkFiles(); //ClientSideBlazor

         app.UseRouting();

         app.UseIdentityServer();
         app.UseAuthentication();
         app.UseAuthorization();

         app.UseMultiTenant();

         using (var serviceScope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope())
         {
            var databaseInitializer = serviceScope.ServiceProvider.GetService<IDatabaseInitializer>();
            databaseInitializer.SeedAsync().Wait();

            var localizationProvider = serviceScope.ServiceProvider.GetService<ILocalizationProvider>();

            var localizationDbContext = serviceScope.ServiceProvider.GetService<LocalizationDbContext>();

            localizationProvider.Init(localizationDbContext.LocalizationRecords.Include(i => i.PluralTranslations), localizationDbContext.PluralFormRules);
         }

         app.UseMiddleware<UserSessionMiddleware>();

         // before app.UseMultiTenant() make injected TenantInfo == null
         app.UseMiddleware<APIResponseRequestLoggingMiddleware>();

         if (_enableAPIDoc)
         {
            app.UseOpenApi();
            app.UseSwaggerUi3(settings =>
            {
               settings.OAuth2Client = new OAuth2ClientSettings()
               {
                  AppName = projectName,
                  ClientId = IdentityServerConfig.SwaggerClientID,
                  UsePkceWithAuthorizationCodeGrant = true
               };
            });
         }

         app.UseEndpoints(endpoints =>
         {
            endpoints.MapDefaultControllerRoute();
            endpoints.MapControllers();

            endpoints.MapBlazorHub();
            endpoints.MapFallbackToPage("/_Index");

            // new SignalR endpoint routing setup
            endpoints.MapHub<Hubs.ChatHub>("/chathub");
         });
      }

#pragma warning disable CS1998
      private async Task HandleOnRemoteFailure(RemoteFailureContext context)
      {
         var msg = context.Failure.Message.Split(Environment.NewLine).Select(s => s + Environment.NewLine).Aggregate((s1, s2) => s1 + s2);

         if (context.Properties != null)
            foreach (var pair in context.Properties.Items)
               msg = $"{msg}{Environment.NewLine}-{pair.Key}={pair.Value}";

         context.Response.Redirect($"/externalauth/error/{ErrorEnum.ExternalAuthError}");

         context.HandleResponse();
      }
   }
}