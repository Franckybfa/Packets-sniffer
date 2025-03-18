import streamlit as st
import pandas as pd
import plotly.express as px
from packet_sniffer import PacketSniffer
from utils import check_root_privileges, format_packet_info
import time

st.set_page_config(page_title="Network Packet Sniffer", layout="wide")

def show_error_page():
    st.error("⚠️ Cette application nécessite des privilèges administrateur pour capturer les paquets réseau.")
    st.markdown("""
    ### Instructions pour lancer l'application :

    1. Ouvrez un terminal
    2. Naviguez vers le dossier de l'application
    3. Exécutez la commande : `sudo streamlit run app.py`

    **Note:** Les privilèges administrateur sont nécessaires pour accéder aux interfaces réseau.
    """)
    return

def main():
    st.title("Analyseur de Paquets Réseau")

    # Vérification des privilèges
    if not check_root_privileges():
        show_error_page()
        return

    # Initialize session state
    if 'sniffer' not in st.session_state:
        st.session_state.sniffer = PacketSniffer()
    if 'packets' not in st.session_state:
        st.session_state.packets = []
    if 'is_capturing' not in st.session_state:
        st.session_state.is_capturing = False

    # Contrôles dans la barre latérale
    with st.sidebar:
        st.header("Contrôles")

        # Sélection de l'interface
        interfaces = st.session_state.sniffer.get_interfaces()
        selected_interface = st.selectbox("Sélectionner l'Interface", interfaces)

        # Options de filtrage
        st.subheader("Filtres")
        protocol_filter = st.multiselect("Filtrer par Protocol", 
                                    ["TCP", "UDP", "ICMP", "Tous"],
                                    default="Tous")

        # Contrôles de capture
        if not st.session_state.is_capturing:
            if st.button("Démarrer la Capture"):
                st.session_state.is_capturing = True
                st.session_state.sniffer.start_capture(
                    interface=selected_interface,
                    protocol_filter=protocol_filter
                )
        else:
            if st.button("Arrêter la Capture"):
                st.session_state.is_capturing = False
                st.session_state.sniffer.stop_capture()

        # Export des données
        if st.session_state.packets:
            st.download_button(
                "Exporter les Données (CSV)",
                data=pd.DataFrame(st.session_state.packets).to_csv(index=False),
                file_name="paquets_captures.csv",
                mime="text/csv"
            )

    # Zone de contenu principal
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Paquets Capturés")

        if st.session_state.is_capturing:
            new_packets = st.session_state.sniffer.get_captured_packets()
            if new_packets:
                st.session_state.packets.extend(new_packets)

        if st.session_state.packets:
            df = pd.DataFrame(st.session_state.packets)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("Aucun paquet capturé. Démarrez la capture pour voir les données.")

    with col2:
        st.subheader("Statistiques")
        if st.session_state.packets:
            df = pd.DataFrame(st.session_state.packets)

            # Distribution des protocoles
            protocol_counts = df['protocol'].value_counts()
            fig1 = px.pie(values=protocol_counts.values, 
                         names=protocol_counts.index, 
                         title="Distribution des Protocoles")
            st.plotly_chart(fig1)

            # Distribution de la taille des paquets
            fig2 = px.histogram(df, x='size', 
                              title="Distribution de la Taille des Paquets",
                              labels={'size': 'Taille des Paquets (octets)'})
            st.plotly_chart(fig2)

    # Actualisation automatique pour les mises à jour en temps réel
    if st.session_state.is_capturing:
        time.sleep(1)
        st.rerun()

if __name__ == "__main__":
    main()