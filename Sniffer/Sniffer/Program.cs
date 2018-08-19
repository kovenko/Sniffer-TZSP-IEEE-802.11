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
                //System.IO.File.WriteAllLines(@"C:\Users\Вадим\source\repos\Sniffer-TZSP-IEEE-802.11\Sniffer\Sniffer\bin\Debug\netcoreapp2.0\Destination.txt", ServerTzsp.DestinationList);
                //System.IO.File.WriteAllLines(@"C:\Users\Вадим\source\repos\Sniffer-TZSP-IEEE-802.11\Sniffer\Sniffer\bin\Debug\netcoreapp2.0\Source.txt", ServerTzsp.SourceList);
                //System.IO.File.WriteAllLines(@"C:\Users\Вадим\source\repos\Sniffer-TZSP-IEEE-802.11\Sniffer\Sniffer\bin\Debug\netcoreapp2.0\Receiver.txt", ServerTzsp.ReceiverList);
                //System.IO.File.WriteAllLines(@"C:\Users\Вадим\source\repos\Sniffer-TZSP-IEEE-802.11\Sniffer\Sniffer\bin\Debug\netcoreapp2.0\Transmitter.txt", ServerTzsp.TransmitterList);
                //System.IO.File.WriteAllLines(@"C:\Users\Вадим\source\repos\Sniffer-TZSP-IEEE-802.11\Sniffer\Sniffer\bin\Debug\netcoreapp2.0\Bssid.txt", ServerTzsp.BssidList);
            };

            ServerTzsp.Run();
            Console.WriteLine("Press a key...");
            Console.ReadKey();
        }
    }
}
