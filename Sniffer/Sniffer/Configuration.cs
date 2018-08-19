using System.IO;
using System.Net;
using Microsoft.Extensions.Configuration;
//using Microsoft.Extensions.Configuration.FileExtensions;
//using Microsoft.Extensions.Configuration.Json;

namespace Sniffer
{
    class Configuration
    {
        private static IConfiguration Config { get; }
        public static IPAddress TzspAddress { get; }
        public static int TzspPort { get; }

        static Configuration()
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("SnifferCinfiguration.json");
            Config = builder.Build();

            TzspAddress = IPAddress.Parse(Config["tzsp_server:address"]);
            TzspPort    = int.Parse(Config["tzsp_server:port"]);
        }
    }
}
