//#define DebugTzsp
//#define DebugIeee802Dot11
//#define DebugIeee802Dot11Breif
//#define DebugManagament
#define DebugControl
//#define DebugData

// Инфо по настоящим подключениям

using System;
//using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace Sniffer
{
    public class ServerTzsp
    {
        private static UdpClient _listener;
        private static bool _shutdown;

        //public static HashSet<string> DestinationList = new HashSet<string>();
        //public static HashSet<string> SourceList      = new HashSet<string>();
        //public static HashSet<string> ReceiverList    = new HashSet<string>();
        //public static HashSet<string> TransmitterList = new HashSet<string>();
        //public static HashSet<string> BssidList       = new HashSet<string>();

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

/*
     00
	Type: Managament; Subtype: Beacon; ToDS: False; FromDS: False;
	Address1: FF-FF-FF-FF-FF-FF; Address2: 00-23-B1-74-41-01; Address3: 00-23-B1-74-41-01;

    Address2
	Type: Managament; Subtype: Probe request; ToDS: False; FromDS: False;
	Address1: FF-FF-FF-FF-FF-FF; Address2: 58-48-22-71-0D-CA; Address3: FF-FF-FF-FF-FF-FF;

	Type: Managament; Subtype: Probe response; ToDS: False; FromDS: False;
	Address1: 58-48-22-71-0D-CA; Address2: 00-23-B1-74-41-01; Address3: 00-23-B1-74-41-01;

	Type: Managament; Subtype: Authentification; ToDS: False; FromDS: False;
	Address1: 58-48-22-71-0D-CA; Address2: 00-23-B1-74-41-01; Address3: 00-23-B1-74-41-01;

    Address2
	Type: Managament; Subtype: Association request; ToDS: False; FromDS: False;
	Address1: 00-23-B1-74-41-01; Address2: 58-48-22-71-0D-CA; Address3: 00-23-B1-74-41-01;

	Type: Managament; Subtype: Association response; ToDS: False; FromDS: False;
	Address1: 58-48-22-71-0D-CA; Address2: 00-23-B1-74-41-01; Address3: 00-23-B1-74-41-01;

	Type: Managament; Subtype: Reserved; ToDS: False; FromDS: False;
	Address1: 00-23-B1-74-41-01; Address2: 58-48-22-71-0D-CA; Address3: 00-23-B1-74-41-01;

	Type: Managament; Subtype: Reserved; ToDS: False; FromDS: False;
	Address1: 58-48-22-71-0D-CA; Address2: 00-23-B1-74-41-01; Address3: 00-23-B1-74-41-01;

	Type: Managament; Subtype: Diassociation; ToDS: False; FromDS: False;
	Address1: 58-48-22-71-0D-CA; Address2: 00-23-B1-74-41-01; Address3: 00-23-B1-74-41-01;

    10 Address2
    Type: Data; Subtype: No data; ToDS: True; FromDS: False;
    Address1: 00-23-B1-74-41-01; Address2: 98-9E-63-91-31-7E; Address3: 00-23-B1-74-41-01;

	Type: Data; Subtype: No data; ToDS: True; FromDS: False; 
	Address1: C0-25-E9-3E-D9-3A; Address2: FC-42-03-3C-04-5A; Address3: C0-25-E9-3E-D9-3A;

    Type: Data; Subtype: No data; ToDS: True; FromDS: False; 
	Address1: C0-25-E9-3E-D9-3A; Address2: 24-0D-C2-27-17-1D; Address3: C0-25-E9-3E-D9-3A;

    Type: Data; Subtype: No data; ToDS: True; FromDS: False;
	Address1: 02-0C-42-C7-6B-9D; Address2: 58-48-22-71-0D-CA; Address3: 02-0C-42-C7-6B-9D;


    01 не понятно
    Type: Data; Subtype: Data; ToDS: False; FromDS: True;
    Address1: FF-FF-FF-FF-FF-FF; Address2: 00-23-B1-74-41-01; Address3: B0-5A-DA-FE-56-5F;

    Type: Data; Subtype: Data; ToDS: False; FromDS: True;
    Address1: FF-FF-FF-FF-FF-FF; Address2: 00-37-B7-C5-8A-F1; Address3: 5C-F4-AB-CF-34-E5;

    Type: Data; Subtype: Data; ToDS: False; FromDS: True;
    Address1: FF-FF-FF-FF-FF-FF; Address2: 00-23-B1-74-41-01; Address3: 00-23-B1-74-2B-E9;

    Type: Data; Subtype: No data; ToDS: False; FromDS: True;
    Address1: 98-9E-63-91-31-7E; Address2: 00-23-B1-74-41-01; Address3: 00-23-B1-74-41-01;

    //Type: Data; Subtype: Data; ToDS: False; FromDS: True;
	//Address1: 01-00-5E-7F-FF-FA; Address2: C0-25-E9-3E-D9-3A; Address3: 40-F0-2F-43-B0-7F;

	//Type: Data; Subtype: Data; ToDS: False; FromDS: True;
	//Address1: FF-FF-FF-FF-FF-FF; Address2: C0-25-E9-3E-D9-3A; Address3: C0-25-E9-3E-D9-3A;

C0-25-E9-3E-D9-3A
AC-F1-DF-2E-5C-C4
02-0C-42-C7-6B-9D ?
*/

/*
#if DebugIeee802Dot11Breif

                            // 00
                            //if (ParserIeee802Dot11.GetSubtype(ieee801Dot11) == "Beacon") break;
                            //if (ParserIeee802Dot11.GetToDs(ieee801Dot11) || ParserIeee802Dot11.GetFromDs(ieee801Dot11)) break;

                            // 10
                            if (ParserIeee802Dot11.GetToDs(ieee801Dot11) && !ParserIeee802Dot11.GetFromDs(ieee801Dot11))
                            {
                                //Console.Write(ParserIeee802Dot11.FrameControlBreifToString(ieee801Dot11));
                            }

                            // 01
                            if (!ParserIeee802Dot11.GetToDs(ieee801Dot11) && ParserIeee802Dot11.GetFromDs(ieee801Dot11))
                            {
                                //Console.Write(ParserIeee802Dot11.FrameControlBreifToString(ieee801Dot11));
                            }
                            // 11
                            if (ParserIeee802Dot11.GetToDs(ieee801Dot11) && ParserIeee802Dot11.GetFromDs(ieee801Dot11))
                            {
                                Console.Write(ParserTzsp.ToString(tzsp));
                                Console.Write(ParserIeee802Dot11.ToString(ieee801Dot11));
                                Console.Write(ParserIeee802Dot11.FrameControlBreifToString(ieee801Dot11));
                            }

#endif
*/
/*
                                if (ParserIeee802Dot11.GetSubtype(ieee801Dot11) == "Beacon")
                                {
                                    string bssid = ParserIeee802Dot11.GetBssidAddress(ieee801Dot11);
                                    BssidList.Add(bssid);
                                    Console.WriteLine($"BSSID: {ParserIeee802Dot11.GetBssidAddress(ieee801Dot11)}");
                                }


string destination = ParserIeee802Dot11.GetDestinationAddress(ieee801Dot11);
BssidList.Add(destination);
Console.WriteLine($"Destination: {ParserIeee802Dot11.GetDestinationAddress(ieee801Dot11)}");

string source = ParserIeee802Dot11.GetSourceAddress(ieee801Dot11);
BssidList.Add(source);
Console.WriteLine($"Source: {ParserIeee802Dot11.GetSourceAddress(ieee801Dot11)}");

string receiver = ParserIeee802Dot11.GetReceiverAddress(ieee801Dot11);
BssidList.Add(receiver);
Console.WriteLine($"Receiver: {ParserIeee802Dot11.GetReceiverAddress(ieee801Dot11)}");

string transmitter = ParserIeee802Dot11.GetTransmitterAddress(ieee801Dot11);
BssidList.Add(transmitter);
Console.WriteLine($"Transmitter: {ParserIeee802Dot11.GetTransmitterAddress(ieee801Dot11)}");

string bssid = ParserIeee802Dot11.GetBssidAddress(ieee801Dot11);
BssidList.Add(bssid);
Console.WriteLine($"Bssid: {ParserIeee802Dot11.GetBssidAddress(ieee801Dot11)}");
*/

/*
                                if (ieee801Dot11.address1[0] != 0x58 || ieee801Dot11.address2[0] != 0x58 ||
                                    ieee801Dot11.address3[0] != 0x58 ||
                                    ieee801Dot11.address4[0] != 0x58) // Test only mac address 58:...
                                {

                                    //if (ParserIeee802Dot11.GetToDs(ieee801Dot11) == true)
                                    //if (ParserIeee802Dot11.GetSubtype(ieee801Dot11) != "Beacon" && ParserIeee802Dot11.GetSubtype(ieee801Dot11) != "Probe request" && ParserIeee802Dot11.GetSubtype(ieee801Dot11) != "Probe response")
                                    //if (!ParserIeee802Dot11.GetToDs(ieee801Dot11) && ParserIeee802Dot11.GetFromDs(ieee801Dot11))
                                    // ParserIeee802Dot11.GetFromDs(ieee801Dot11) == true receiver_address
                                    // ParserIeee802Dot11.GetDs(ieee801Dot11) == true transmitter_address
                                    //Console.Write(ParserIeee802Dot11.ToString(ieee801Dot11));
                                    //Console.Write(ParserIeee802Dot11.FrameControlBreifToString(ieee801Dot11));
                                }

 
Protocol IEEE 802.11 parser
Encapsulated packet length 24 bytes; 08-42-00-00-FF-FF-FF-FF-FF-FF-00-23-B1-74-41-01-00-23-B1-74-2B-E9-A0-75
        FrameControl: 16904
        Duration: 0
        Address1: FF-FF-FF-FF-FF-FF dest
        Address2: 00-23-B1-74-41-01 bssid
        Address3: 00-23-B1-74-2B-E9 source
        SequenceControl: 30112

        Type: Data; Subtype: Data; ToDS: False; FromDS: True;
        Address1: FF-FF-FF-FF-FF-FF; Address2: 00-23-B1-74-41-01; Address3: 00-23-B1-74-2B-E9;

Protocol IEEE 802.11 parser
Encapsulated packet length 24 bytes; 48-11-3C-00-00-23-B1-74-41-01-38-A4-ED-43-85-B9-00-23-B1-74-41-01-40-97
        FrameControl: 4424
        Duration: 60
        Address1: 00-23-B1-74-41-01
        Address2: 38-A4-ED-43-85-B9
        Address3: 00-23-B1-74-41-01
        SequenceControl: 38720

        Type: Data; Subtype: No data; ToDS: True; FromDS: False;
        Address1: 00-23-B1-74-41-01; Address2: 38-A4-ED-43-85-B9; Address3: 00-23-B1-74-41-01;

     
     
     */
