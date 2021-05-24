using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Mcrio.Configuration.Provider.Docker.Secrets;
using Microsoft.Extensions.Logging;

namespace BlazorBoilerplate.Server
{
   public class Program
   {
      public static void Main(string[] args)
      {
         CreateHostBuilder(args).Build().Run();
      }

      public static IHostBuilder CreateHostBuilder(string[] args) =>
         Host.CreateDefaultBuilder(args)
            .ConfigureLogging(logging =>
            {
               logging.ClearProviders();
               // We have to be precise on the logging levels
               logging.AddConsole();
               logging.AddDebug();
            })
            .ConfigureAppConfiguration(configBuilder =>
            {
               configBuilder.AddDockerSecrets();
            })
            .ConfigureWebHostDefaults(webBuilder =>
            {
               webBuilder.UseStartup<Startup>();
            });

   }
}
