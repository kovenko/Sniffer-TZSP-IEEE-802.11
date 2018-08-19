// https://habr.com/post/129207/
// https://developers.redhat.com/blog/2017/06/07/writing-a-linux-daemon-in-c/
// https://stackoverflow.com/questions/41454563/how-to-write-a-linux-daemon-with-net-core
// https://logankpaschke.com/linux/systemd/dotnet/systemd-dotnet-1/
// https://github.com/jirihnidek/daemon

using System;

namespace Sniffer
{
    class Program
    {
        private static void Main()
        {
            Console.CancelKeyPress += (s, ev) =>
            {
                Console.WriteLine("Ctrl+C pressed");
                ev.Cancel = true;
                ServerTzsp.Close();
            };

            ServerTzsp.Run();
            Console.WriteLine("Press a key...");
            Console.ReadKey();
        }
    }
}
