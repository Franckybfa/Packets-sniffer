import os
import sys
import queue
from scapy.all import sniff, conf, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from threading import Thread, Event

class PacketSniffer:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture_event = Event()
        self.capture_thread = None

    def get_interfaces(self):
        """Obtenir la liste des interfaces réseau disponibles sous Windows."""
        return get_if_list()

    def packet_callback(self, packet):
        """Callback pour traiter les paquets capturés."""
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
        """Déterminer le protocole du paquet."""
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        return 'Other'

    def _get_packet_info(self, packet):
        """Extraire les informations supplémentaires du paquet."""
        if TCP in packet:
            return f"Port: {packet[TCP].sport} → {packet[TCP].dport}"
        elif UDP in packet:
            return f"Port: {packet[UDP].sport} → {packet[UDP].dport}"
        elif ICMP in packet:
            return f"ICMP Type: {packet[ICMP].type}"
        return "No additional info"

    def start_capture(self, interface, protocol_filter=None):
        """Démarrer la capture de paquets sur une interface spécifique."""
        if not self._is_admin():
            print("⚠️ Exécutez ce script en tant qu'administrateur pour capturer les paquets sur Windows.")
            return

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
                print(f"Erreur de capture : {e}")

        self.stop_capture_event.clear()
        self.capture_thread = Thread(target=capture_thread)
        self.capture_thread.start()

    def stop_capture(self):
        """Arrêter la capture de paquets."""
        self.stop_capture_event.set()
        if self.capture_thread:
            self.capture_thread.join()

    def get_captured_packets(self):
        """Récupérer les paquets capturés."""
        packets = []
        while not self.packet_queue.empty():
            packets.append(self.packet_queue.get())
        return packets

    def _is_admin(self):
        """Vérifier si le script est exécuté en mode administrateur."""
        try:
            return os.getuid() == 0
        except AttributeError:
            return bool(os.system("net session >nul 2>&1") == 0)


# Exécution du script de test
if __name__ == "__main__":
    sniffer = PacketSniffer()
    interfaces = sniffer.get_interfaces()
    print("Interfaces disponibles :", interfaces)

    if interfaces:
        chosen_interface = interfaces[0]  # Sélection de la première interface (modifiable)
        print(f"📡 Démarrage de la capture sur {chosen_interface}...")
        sniffer.start_capture(chosen_interface, protocol_filter=["tcp", "udp"])
    else:
        print("⚠️ Aucune interface réseau détectée.")
