//#define DebugTzsp
//#define DebugIeee802Dot11
//#define DebugIeee802Dot11Breif
//#define DebugManagament
#define DebugControl
//#define DebugData

// Инфо по настоящим подключениям

using System;
using System.Net;
using System.Net.Sockets;

namespace Sniffer
{
    public class ServerTzsp
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
            _listener   = new UdpClient(Configuration.TzspPort);
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
# if DebugTzsp
                        Console.Write(ParserTzsp.ToString(tzsp));
#endif
                        // Parsing encapsulated packet
                        switch (ParserTzsp.GetProtocol(tzsp.header.encapsulated_protocol))
                        {
                            case "Ieee802Dot11":
                                try
                                {
                                    var ieee801Dot11 = ParserIeee802Dot11.Parse(tzsp.encapsulated_packet);
#if DebugIeee802Dot11
                                    Console.Write(ParserIeee802Dot11.ToString(ieee801Dot11));
#endif
#if DebugIeee802Dot11Breif
                                    Console.Write(ParserIeee802Dot11.FrameControlBreifToString(ieee801Dot11));
#endif
#if DebugManagament
                                    if (ParserIeee802Dot11.IsManagament(ieee801Dot11) && ParserIeee802Dot11.GetSubtype(ieee801Dot11) == "Beacon")
                                    {
                                        Console.Write(ParserIeee802Dot11.ToString(ieee801Dot11));
                                        Console.Write(ParserIeee802Dot11.FrameControlBreifToString(ieee801Dot11));
                                    }
#endif

#if DebugControl
                                    if (ParserIeee802Dot11.IsControl(ieee801Dot11))
                                    {
                                        Console.Write(ParserIeee802Dot11.ToString(ieee801Dot11));
                                        Console.Write(ParserIeee802Dot11.FrameControlBreifToString(ieee801Dot11));
                                    }
#endif

#if DebugData
                                    if (ParserIeee802Dot11.IsData(ieee801Dot11))
                                    {
                                        Console.Write(ParserIeee802Dot11.ToString(ieee801Dot11));
                                        Console.Write(ParserIeee802Dot11.FrameControlBreifToString(ieee801Dot11));
                                    }
#endif
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine($"Encapsulated packet not is IEEE 802.11 {e.Message ?? ""}");
                                    Console.WriteLine($"Encapsulated packet length {tzsp.encapsulated_packet.Length} bytes; {BitConverter.ToString(tzsp.encapsulated_packet)}");
                                    Console.WriteLine("");
                                }
                              break;
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Packet not is TZSP {e.Message ?? ""}");
                        Console.WriteLine($"Reseived packet length {packet.Length} bytes; {BitConverter.ToString(packet)}");
                        Console.WriteLine("");
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
