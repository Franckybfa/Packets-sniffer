import os
import sys
import streamlit as st
import pandas as pd
import plotly.express as px
import time
from packet_sniffer import PacketSniffer
from scapy.all import get_if_list

st.set_page_config(page_title="Network Packet Sniffer", layout="wide")

def check_admin_privileges():
    """ Vérifie si l'application est lancée en mode administrateur (Windows) """
    try:
        return os.getuid() == 0  # UNIX-like
    except AttributeError:
        return bool(os.system("net session >nul 2>&1") == 0)  # Windows

def show_error_page():
    """ Affichage du message d'erreur si l'utilisateur n'a pas les droits admin """
    st.error("⚠️ Cette application nécessite des privilèges administrateur pour capturer les paquets réseau.")
    st.markdown("""
    ### Instructions pour lancer l'application sur Windows :

    1. **Ouvrez un terminal en mode administrateur**  
    2. **Naviguez jusqu'au dossier de l'application**  
    3. **Exécutez la commande suivante** :  
       ```sh
       streamlit run app.py
       ```
    """)
    return

def main():
    st.title("Analyseur de Paquets Réseau")

    # Vérification des droits administrateurs
    if not check_admin_privileges():
        show_error_page()
        return

    # Initialisation de la session Streamlit
    if 'sniffer' not in st.session_state:
        st.session_state.sniffer = PacketSniffer()
    if 'packets' not in st.session_state:
        st.session_state.packets = []
    if 'is_capturing' not in st.session_state:
        st.session_state.is_capturing = False

    # Sidebar: Sélection des paramètres
    with st.sidebar:
        st.header("🔧 Paramètres")

        # Sélection de l'interface réseau
        interfaces = get_if_list()
        selected_interface = st.selectbox("📡 Interface Réseau :", interfaces)

        # Options de filtrage
        st.subheader("🎛️ Filtres")
        protocol_filter = st.multiselect("📌 Protocoles :", ["TCP", "UDP", "ICMP", "Tous"], default="Tous")

        # Démarrage ou arrêt de la capture
        if not st.session_state.is_capturing:
            if st.button("▶️ Démarrer la Capture"):
                st.session_state.is_capturing = True
                st.session_state.sniffer.start_capture(
                    interface=selected_interface,
                    protocol_filter=protocol_filter
                )
        else:
            if st.button("⏹️ Arrêter la Capture"):
                st.session_state.is_capturing = False
                st.session_state.sniffer.stop_capture()

        # Exportation des données
        if st.session_state.packets:
            st.download_button(
                "💾 Exporter en CSV",
                data=pd.DataFrame(st.session_state.packets).to_csv(index=False),
                file_name="paquets_captures.csv",
                mime="text/csv"
            )

    # Affichage des données capturées
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("📊 Paquets Capturés")

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
        st.subheader("📈 Statistiques")
        if st.session_state.packets:
            df = pd.DataFrame(st.session_state.packets)

            # Graphique des protocoles
            protocol_counts = df['protocol'].value_counts()
            fig1 = px.pie(values=protocol_counts.values, names=protocol_counts.index, title="📡 Distribution des Protocoles")
            st.plotly_chart(fig1)

            # Histogramme des tailles des paquets
            fig2 = px.histogram(df, x='size', title="📏 Distribution de la Taille des Paquets", labels={'size': 'Taille (octets)'})
            st.plotly_chart(fig2)

    # Mise à jour automatique pour l'affichage en temps réel
    if st.session_state.is_capturing:
        st.rerun()

if __name__ == "__main__":
    main()
