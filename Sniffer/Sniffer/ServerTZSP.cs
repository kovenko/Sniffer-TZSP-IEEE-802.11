using System;
using System.Net;
using System.Net.Sockets;

namespace Sniffer
{
    internal static class ServerTzsp
    {
        private static UdpClient _listener;
        private static bool _shutdown;

        public static void Close()
        {
            _shutdown = true;
            _listener.Close();
        }

        public static void Run()
        {
            if (Configuration.TzspPort == -1) { }
            _listener          = new UdpClient(Configuration.TzspPort);
            var groupEp = new IPEndPoint(Configuration.TzspAddress, Configuration.TzspPort);
            Console.WriteLine($"Server TZSP starded IP Address: {Configuration.TzspAddress} Port: {Configuration.TzspPort.ToString()}");
            try
            {
                while (!_shutdown)
                {
                    var packet = _listener.Receive(ref groupEp);
                    try
                    {
                        // Parsing TZSP
                        var tzsp = ParserTzsp.Parse(packet);
                        ParserTzsp.ToString(tzsp);
                        
                        // Parsing encapsulated packet
                        switch (ParserTzsp.GetProtocol(tzsp.header.encapsulated_protocol))
                        {
                            case "Ieee802Dot11":
                                var ieee801Dot11 = ParserIeee802Dot11.Parse(tzsp.encapsulated_packet);
                                //if (ieee801Dot11.receiver_address[0] == 0x58 || ieee801Dot11.transmitter_address[0] == 0x58 || ieee801Dot11.destination_address[0] == 0x58) // Test only mac address 58:...
                                {
                                    ParserIeee802Dot11.ToString(ieee801Dot11);
                                    ParserIeee802Dot11.FrameControlToString(ieee801Dot11);
                                }
                                break;
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Reseived packet length {packet.Length} bytes; {BitConverter.ToString(packet)}");
                        Console.WriteLine($"Packet not is TZSP /{e.Message}/");
                    }
                }
            }
            catch (Exception e)
            {
                if (!_shutdown) Console.WriteLine(e.ToString());
            }
            finally
            {
                _listener.Close();
            }
            Console.WriteLine("Server TZSP stopped");
        }
    }
}
