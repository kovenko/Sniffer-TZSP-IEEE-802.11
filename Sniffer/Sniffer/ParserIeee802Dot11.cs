using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace Sniffer
{
    public class ParserIeee802Dot11
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct Ieee802Dot11Packet
        {
            public ushort frame_control;
            public ushort duration;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] address1;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] address2;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] address3;

            public ushort sequence_control;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] address4;

            public byte[] frame_body;
            public uint? fcs;
            public byte[] packet;
        };

        public static Ieee802Dot11Packet Parse(byte[] packet)
        {
            if (packet.Length < 24)
            {
                throw new Exception("/Its no IEEE 802.11 packet/");
            }

            var result = new Ieee802Dot11Packet
            {
                packet = packet,
                frame_control = GetFrameControl(packet),
                duration = GetDuration(packet),
                address1 = GetAddress(packet, 4),
                address2 = GetAddress(packet, 10),
                address3 = GetAddress(packet, 16),
                sequence_control = GetSequenceControl(packet),
                address4 = GetAddress(packet, 24),
                frame_body = GetFrameBody(packet),
                fcs = GetFcs(packet)
            };
            if (GetVersion(result) != "0") throw new Exception("/Its no IEEE 802.11 packet/");
            return result;
        }

        private static ushort GetFrameControl(byte[] s)
        {
            var networkByte = BitConverter.ToInt16(s, 0);
            return (ushort) networkByte;
        }

        private static ushort GetDuration(byte[] s)
        {
            var networkByte = BitConverter.ToInt16(s, 2);
            return (ushort) networkByte;
        }

        private static byte[] GetAddress(byte[] s, int offset)
        {
            if (s.Length < offset + 6) return null;
            var address = new byte[6];
            Array.Copy(s, offset, address, 0, 6);
            return address;
        }

        private static ushort GetSequenceControl(byte[] s)
        {
            var networkByte = BitConverter.ToInt16(s, 22);
            return (ushort) networkByte;
        }

        private static byte[] GetFrameBody(byte[] s)
        {
            if (s.Length <= 34) return null;

            var frameBoby = new byte[s.Length - 34];
            Array.Copy(s, 30, frameBoby, 0, s.Length - 34);
            return frameBoby;
        }

        private static uint? GetFcs(byte[] s)
        {
            if (s.Length < 34) return null;

            var networkByte = BitConverter.ToUInt32(s, s.Length - 4);
            return networkByte;
        }

        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        public static string GetDestinationAddress(Ieee802Dot11Packet ieee801Dot11)
        {
            bool fromDs = GetFromDs(ieee801Dot11);
            bool toDs = GetToDs(ieee801Dot11);
            if ((!toDs && !fromDs) || (!toDs)) return BitConverter.ToString(ieee801Dot11.address1).Replace("-", ":");
            return BitConverter.ToString(ieee801Dot11.address3).Replace("-", ":");
        }

        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        public static string GetSourceAddress(Ieee802Dot11Packet ieee801Dot11)
        {
            bool fromDs = GetFromDs(ieee801Dot11);
            bool toDs = GetToDs(ieee801Dot11);
            if ((!toDs && !fromDs) || (toDs && !fromDs)) return BitConverter.ToString(ieee801Dot11.address2).Replace("-", ":");
            if (!toDs) return BitConverter.ToString(ieee801Dot11.address3).Replace("-", ":");
            return BitConverter.ToString(ieee801Dot11.address4).Replace("-", ":");
        }

        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        public static string GetReceiverAddress(Ieee802Dot11Packet ieee801Dot11)
        {
            bool fromDs = GetFromDs(ieee801Dot11);
            bool toDs = GetToDs(ieee801Dot11);
            if (toDs && fromDs) return BitConverter.ToString(ieee801Dot11.address1).Replace("-", ":");
            return null;
        }

        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        public static string GetTransmitterAddress(Ieee802Dot11Packet ieee801Dot11)
        {
            bool fromDs = GetFromDs(ieee801Dot11);
            bool toDs = GetToDs(ieee801Dot11);
            if (toDs && fromDs) return BitConverter.ToString(ieee801Dot11.address2).Replace("-", ":");
            return null;
        }

        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        public static string GetBssidAddress(Ieee802Dot11Packet ieee801Dot11)
        {
            bool fromDs = GetFromDs(ieee801Dot11);
            bool toDs = GetToDs(ieee801Dot11);
            if (!toDs && !fromDs) return BitConverter.ToString(ieee801Dot11.address3).Replace("-", ":");
            if (!toDs) return BitConverter.ToString(ieee801Dot11.address2).Replace("-", ":");
            if (!fromDs) return BitConverter.ToString(ieee801Dot11.address1).Replace("-", ":");
            return null;
        }

        [SuppressMessage("ReSharper", "UnusedMember.Local")]
        private static string GetGadgetAddress(Ieee802Dot11Packet ieee801Dot11)
        {
            if (GetType(ieee801Dot11) == "Managament" && (GetSubtype(ieee801Dot11) == "Probe request" || GetSubtype(ieee801Dot11) == "Association request"))
            {
                return BitConverter.ToString(ieee801Dot11.address2).Replace("-", ":");
            }
            return null;
        }

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public static string ToString(Ieee802Dot11Packet ieee801Dot11)
        {
            string result = "Protocol IEEE 802.11 parser\n";
            result += $"Encapsulated packet length {ieee801Dot11.packet.Length} bytes; {BitConverter.ToString(ieee801Dot11.packet)}\n";
            result += $"\tFrameControl: {ieee801Dot11.frame_control}\n";
            result += $"\tDuration: {ieee801Dot11.duration}\n";
            result += $"\tAddress1: {BitConverter.ToString(ieee801Dot11.address1)}\n";
            result += $"\tAddress2: {BitConverter.ToString(ieee801Dot11.address2)}\n";
            result += $"\tAddress3: {BitConverter.ToString(ieee801Dot11.address3)}\n";
            result += $"\tSequenceControl: {ieee801Dot11.sequence_control}\n";
            if (ieee801Dot11.address4 != null) result += $"\tAddress4: {BitConverter.ToString(ieee801Dot11.address4)}\n";
            if (ieee801Dot11.frame_body != null) result += $"\tFrameBody: {BitConverter.ToString(ieee801Dot11.frame_body)}\n";
            if (ieee801Dot11.frame_body != null) result += $"\tFCS: {ieee801Dot11.fcs}\n";
            result += "\n";
            return result;
        }

        // Parse FrameControl

        public static string FrameControlBreifToString(Ieee802Dot11Packet ieee801Dot11)
        {
            string result = $"\tType: {GetType(ieee801Dot11)}; Subtype: {GetSubtype(ieee801Dot11)}; ToDS: {GetToDs(ieee801Dot11).ToString()}; FromDS: {GetFromDs(ieee801Dot11).ToString()};\n";
            result += $"\tAddress1: {BitConverter.ToString(ieee801Dot11.address1)}; Address2: {BitConverter.ToString(ieee801Dot11.address2)}; Address3: {BitConverter.ToString(ieee801Dot11.address3)};";
            if (ieee801Dot11.address4 != null) result += $" Address4: {BitConverter.ToString(ieee801Dot11.address4)}";
            result += "\n";
            result += "\n";
            return result;
        }

        [SuppressMessage("ReSharper", "UnusedMember.Global")]
        public static string FrameControlToString(Ieee802Dot11Packet ieee801Dot11)
        {
            string result = $"\tFramecontrol: Version: {GetVersion(ieee801Dot11)}; Type: {GetType(ieee801Dot11)}; Subtype: {GetSubtype(ieee801Dot11)}; ToDS: {GetToDs(ieee801Dot11).ToString()}; FromDS: {GetFromDs(ieee801Dot11).ToString()};\n";
            result += $"\tAddress1: {BitConverter.ToString(ieee801Dot11.address1)}; Address2: {BitConverter.ToString(ieee801Dot11.address2)}; Address3: {BitConverter.ToString(ieee801Dot11.address3)};\n";
            result += "\n";
            return result;
        }

        public static string GetVersion(Ieee802Dot11Packet ieee801Dot11)
        {
            var version = ieee801Dot11.frame_control & 0x0003;
            return version.ToString();
        }

        public static string GetType(Ieee802Dot11Packet ieee801Dot11)
        {
            var type = (ieee801Dot11.frame_control & 0x000c) >> 2;
            switch (type)
            {
                case 0: return "Managament";
                case 1: return "Control";
                case 2: return "Data";
                default: return "Reserved";
            }
        }
        
        public static string GetSubtype(Ieee802Dot11Packet ieee801Dot11)
        {
            var type = (ieee801Dot11.frame_control & 0x000c) >> 2;
            var subtype = (ieee801Dot11.frame_control & 0x00f0) >> 4;
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

        public static bool GetToDs(Ieee802Dot11Packet ieee801Dot11)
        {
            return (ieee801Dot11.frame_control & 0x0100) > 0;
        }

        public static bool GetFromDs(Ieee802Dot11Packet ieee801Dot11)
        {
            return (ieee801Dot11.frame_control & 0x0200) > 0;
        }

        public static bool IsManagament(Ieee802Dot11Packet ieee801Dot11)
        {
            return (GetType(ieee801Dot11) == "Managament" && GetSubtype(ieee801Dot11) != "Reserved");
        }

        public static bool IsControl(Ieee802Dot11Packet ieee801Dot11)
        {
            return (GetType(ieee801Dot11) == "Control" && GetSubtype(ieee801Dot11) != "Reserved");
        }

        public static bool IsData(Ieee802Dot11Packet ieee801Dot11)
        {
            return (GetType(ieee801Dot11) == "Data" && GetSubtype(ieee801Dot11) != "Reserved");
        }
    }
}
