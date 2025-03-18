import os

def check_root_privileges():
    """Check if the application is running with root privileges."""
    return os.geteuid() == 0

def format_packet_info(packet_info):
    """Format packet information for display."""
    return {
        'timestamp': f"{packet_info['timestamp']:.6f}",
        'source': packet_info['source'],
        'destination': packet_info['destination'],
        'protocol': packet_info['protocol'],
        'size': packet_info['size'],
        'info': packet_info['info']
    }