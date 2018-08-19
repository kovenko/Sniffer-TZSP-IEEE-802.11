using System;
using System.Runtime.InteropServices;

namespace Sniffer
{
    internal static class ParserIeee802Dot11
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct Ieee802Dit11Packet
        {
            public ushort frame_control;
            public ushort duration;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] receiver_address;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] transmitter_address;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] destination_address;
            public ushort sequence_control;
            public byte [] frame_body;
            public byte [] packet;
        };
        
        public static Ieee802Dit11Packet Parse(byte[] packet)
        {
            if (packet.Length < 24)
            {
                throw new Exception("Can't parse packet");
            }

            var result = new Ieee802Dit11Packet
            {
                frame_control = GetFrameControl(packet),
                duration = GetDuration(packet),
                receiver_address = GetReceiverAddress(packet),
                transmitter_address = GetTransmitterAddress(packet),
                destination_address = GetDestinationAddress(packet),
                sequence_control = GetSequenceControl(packet),
                frame_body = GetFrameBody(packet),
                packet = packet
            };
            return result;
        }

        private static ushort GetFrameControl(byte[] s)
        {
            var networkByte = BitConverter.ToInt16(s, 0);
            return (ushort)networkByte;
        }

        private static ushort GetDuration(byte[] s)
        {
            var networkByte = BitConverter.ToInt16(s, 2);
            return (ushort)networkByte;
        }

        private static byte[] GetReceiverAddress(byte[] s)
        {
            var address = new byte[6];
            Array.Copy(s, 4, address, 0, 6);
            return address;
        }

        private static byte[] GetTransmitterAddress(byte[] s)
        {
            var address = new byte[6];
            Array.Copy(s, 10, address, 0, 6);
            return address;
        }

        private static byte[] GetDestinationAddress(byte[] s)
        {
            var address = new byte[6];
            Array.Copy(s, 16, address, 0, 6);
            return address;
        }

        private static ushort GetSequenceControl(byte[] s)
        {
            var networkByte = BitConverter.ToInt16(s, 22);
            return (ushort)networkByte;
        }

        private static byte[] GetFrameBody(byte[] s)
        {
            if (s.Length <= 24) return null;

            var frameBoby = new byte[s.Length - 24];
            Array.Copy(s, 24, frameBoby, 0, s.Length - 24);
            return frameBoby;
        }

        public static void ToString(Ieee802Dit11Packet ieee801Dot11)
        {
            Console.WriteLine("Protocol IEEE 802.11 parser");
            Console.WriteLine($"Encapsulated packet length {ieee801Dot11.packet.Length} bytes; {BitConverter.ToString(ieee801Dot11.packet)}");
            Console.WriteLine($"\tFrameControl: {ieee801Dot11.frame_control}");
            Console.WriteLine($"\tDuration: {ieee801Dot11.duration}");
            Console.WriteLine($"\tReceiverAddress: {BitConverter.ToString(ieee801Dot11.receiver_address)}");
            Console.WriteLine($"\tTransmitterAddress: {BitConverter.ToString(ieee801Dot11.transmitter_address)}");
            Console.WriteLine($"\tDestinationAddress: {BitConverter.ToString(ieee801Dot11.destination_address)}");
            Console.WriteLine($"\tSequenceControl: {ieee801Dot11.sequence_control}");
            if (ieee801Dot11.frame_body != null) Console.WriteLine($"\tFrameBody: {BitConverter.ToString(ieee801Dot11.frame_body)}");
            Console.WriteLine("");
        }

        public static void FrameControlToString(Ieee802Dit11Packet ieee801Dot11)
        {
            var frameControl = ieee801Dot11.frame_control;
            var toDs = (frameControl & 0x0100) > 0;
            var fromDs = (frameControl & 0x0200) > 0;
            Console.WriteLine($"\tFramecontrol: Version: {GetVersion(frameControl)}; Type: {GetType(frameControl)}; Subtype: {GetSubtype(frameControl)}; ToDS: {toDs}; FromDS: {fromDs};");
            Console.WriteLine($"\tTransmitterAddress: {BitConverter.ToString(ieee801Dot11.transmitter_address)}; ReceiverAddress: {BitConverter.ToString(ieee801Dot11.receiver_address)}; DestinationAddress: {BitConverter.ToString(ieee801Dot11.destination_address)};");
            Console.WriteLine("");
        }

        private static string GetVersion(ushort frameControl)
        {
            var version = frameControl & 0x0003;
            return version.ToString();
        }

        private static string GetType(ushort frameControl)
        {
            var type = (frameControl & 0x000c) >> 2;
            switch (type)
            {
                case 0: return "Managament";
                case 1: return "Control";
                case 2: return "Data";
                default: return "Reserved";
            }
        }
        
        private static string GetSubtype(ushort frameControl)
        {
            var type = (frameControl & 0x000c) >> 2;
            var subtype = (frameControl & 0x00f0) >> 4;
            switch (type)
            {
                case 0:
                    switch (subtype)
                    {
                        case 0: return "Association request";
                        case 1: return "Association response";
                        case 2: return "Reassociation request";
                        case 3: return "Association response";
                        case 4: return "Probe request";
                        case 5: return "Probe response";
                        case 8: return "Beacon";
                        case 9: return "ATIM";
                        case 10: return "Diassociation";
                        case 11: return "Authentification";
                        case 12: return "Deauthentification";
                        default: return "Reserved";
                    }
                case 1: 
                    switch (subtype)
                    {
                        case 10: return "Power save";
                        case 11: return "Request to send";
                        case 12: return "Clear to send";
                        case 13: return "Acknowledgment";
                        case 15: return "CF-End + CF-Ack";
                        default: return "Reserved";
                    }
                case 2: 
                    switch (subtype)
                    {
                        case 0: return "Data";
                        case 1: return "Data + CF-Ack";
                        case 2: return "Data + CF-Pull";
                        case 3: return "Data + CF-Ack + CF-Pull";
                        case 4: return "No data";
                        case 5: return "CF-Ack (no data)";
                        case 6: return "CF-Pull (no data)";
                        case 7: return "CF-Ack + CF-Pull (no data)";
                        default: return "Reserved";
                    }
                default: return "Reserved";
            }
        }
    }
}
