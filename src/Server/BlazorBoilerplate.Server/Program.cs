using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Serilog;
using System;
using Mcrio.Configuration.Provider.Docker.Secrets;

namespace BlazorBoilerplate.Server
{
   public class Program
   {
      public static int Main(string[] args)
      {
         var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production";

         var configuration = new ConfigurationBuilder()
             .AddJsonFile("appsettings.json")
             .AddJsonFile($"appsettings.{environment}.json", optional: true)
             .Build();

         Log.Logger = new LoggerConfiguration()
             .ReadFrom.Configuration(configuration)
             .CreateLogger();

         try
         {
            Log.Information("Starting BlazorBoilerplate web server host");
            CreateHostBuilder(args).Build().Run();
            return 0;
         }
         catch (Exception ex)
         {
            Log.Fatal(ex, "BlazorBoilerplate Host terminated unexpectedly");
            return 1;
         }
      }

      public static IHostBuilder CreateHostBuilder(string[] args) =>
          Host.CreateDefaultBuilder(args).ConfigureWebHostDefaults(webBuilder =>
          {
             webBuilder.UseConfiguration(new ConfigurationBuilder()
                   .AddCommandLine(args)
                   .Build());
             webBuilder.ConfigureAppConfiguration(configBuilder =>
               {
                 configBuilder.AddDockerSecrets();
              });
             webBuilder.UseStartup<Startup>();
             webBuilder.UseSerilog();
          });
   }
}
