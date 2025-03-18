from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from threading import Thread, Event
import queue

class PacketSniffer:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture_event = Event()
        self.capture_thread = None

    def get_interfaces(self):
        """Get list of available network interfaces."""
        return conf.ifaces.data.keys()

    def packet_callback(self, packet):
        """Callback function for processing captured packets."""
        if IP in packet:
            packet_info = {
                'timestamp': packet.time,
                'source': packet[IP].src,
                'destination': packet[IP].dst,
                'protocol': self._get_protocol(packet),
                'size': len(packet),
                'info': self._get_packet_info(packet)
            }
            self.packet_queue.put(packet_info)

    def _get_protocol(self, packet):
        """Determine the protocol of the packet."""
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        return 'Other'

    def _get_packet_info(self, packet):
        """Extract additional information from the packet."""
        if TCP in packet:
            return f"Port: {packet[TCP].sport} → {packet[TCP].dport}"
        elif UDP in packet:
            return f"Port: {packet[UDP].sport} → {packet[UDP].dport}"
        elif ICMP in packet:
            return f"ICMP Type: {packet[ICMP].type}"
        return "No additional info"

    def start_capture(self, interface, protocol_filter=None):
        """Start packet capture on specified interface."""
        filter_str = ""
        if protocol_filter and "Tous" not in protocol_filter:
            filter_str = " or ".join(p.lower() for p in protocol_filter)

        def capture_thread():
            try:
                sniff(iface=interface,
                     prn=self.packet_callback,
                     filter=filter_str,
                     store=0,
                     stop_filter=lambda _: self.stop_capture_event.is_set())
            except Exception as e:
                print(f"Capture error: {e}")

        self.stop_capture_event.clear()
        self.capture_thread = Thread(target=capture_thread)
        self.capture_thread.start()

    def stop_capture(self):
        """Stop the packet capture."""
        self.stop_capture_event.set()
        if self.capture_thread:
            self.capture_thread.join()

    def get_captured_packets(self):
        """Get captured packets from the queue."""
        packets = []
        while not self.packet_queue.empty():
            packets.append(self.packet_queue.get())
        return packets