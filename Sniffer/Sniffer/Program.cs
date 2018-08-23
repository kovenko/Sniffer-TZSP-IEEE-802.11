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
