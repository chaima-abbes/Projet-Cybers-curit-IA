import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from sklearn.metrics import classification_report, confusion_matrix
import plotly.express as px
import time

# Configuration de la page
st.set_page_config(page_title="Détection SSH par IA", layout="wide")
st.title("🛡️ Dashboard IA - Détection d'attaques SSH par force brute")

# Chargement des données et du modèle
@st.cache_data
def load_data():
    df = pd.read_csv("ssh_attacks.csv")
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    return df

@st.cache_resource
def load_model():
    return joblib.load("ssh_attack_detector.pkl")

df = load_data()
model = load_model()

# Ajout de quelques éléments visuels
st.markdown("""
Cette application vous permet de visualiser et de tester un modèle IA qui détecte les tentatives d'attaques SSH en temps réel.
Elle est basée sur un modèle Random Forest entraîné à partir de logs d'authentification.
""")

# Sidebar - Filtres utilisateur
st.sidebar.header("🔍 Filtres")
user_filter = st.sidebar.multiselect("Utilisateur(s)", df['user'].unique())
ip_filter = st.sidebar.multiselect("Adresse IP(s)", df['ip'].unique())

if user_filter:
    df = df[df['user'].isin(user_filter)]
if ip_filter:
    df = df[df['ip'].isin(ip_filter)]

# Graphiques interactifs
st.subheader("📊 Tentatives de connexion SSH")
fig = px.scatter(df, x='timestamp', y='attempts', color='status', hover_data=['ip', 'user'],
                 title="Tentatives SSH au fil du temps")
st.plotly_chart(fig, use_container_width=True)

# Statistiques de base
st.subheader("📈 Statistiques")
col1, col2, col3 = st.columns(3)
col1.metric("Total de tentatives", len(df))
col2.metric("Adresses IP uniques", df['ip'].nunique())
col3.metric("Utilisateurs uniques", df['user'].nunique())

# Rapport de performance (statique ou dynamique)
st.subheader("🧠 Performance du modèle")
y = df['is_attack'] if 'is_attack' in df else None
features = ['hour', 'minute', 'ip_encoded', 'user_encoded', 'attempts', 'time_diff']

if all(f in df.columns for f in features):
    X = df[features].fillna(0)
    y_pred = model.predict(X)
    if y is not None:
        report = classification_report(y, y_pred, output_dict=True)
        st.json(report)
        cm = confusion_matrix(y, y_pred)
        fig, ax = plt.subplots()
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax)
        ax.set_title("Matrice de confusion")
        ax.set_xlabel("Prédit")
        ax.set_ylabel("Réel")
        st.pyplot(fig)
    else:
        st.info("Pas de vérité terrain disponible pour afficher le rapport.")

# Simulation en temps réel
st.subheader("⚡️ Simulation en temps réel")
sample_size = st.slider("Nombre de connexions à simuler", 5, 50, 10)

start_simulation = st.button("Démarrer la simulation")
if start_simulation:
    for _, row in df.sample(sample_size).iterrows():
        hour = pd.to_datetime(row['timestamp'], errors='coerce').hour or 0
        minute = pd.to_datetime(row['timestamp'], errors='coerce').minute or 0

        input_data = pd.DataFrame.from_dict({
            'hour': [hour],
            'minute': [minute],
            'ip_encoded': [row.get('ip_encoded', 0)],
            'user_encoded': [row.get('user_encoded', 0)],
            'attempts': [row['attempts']],
            'time_diff': [row.get('time_diff', 0)]
        })

        pred = model.predict(input_data)[0]
        label = '🔴 ATTAQUE' if pred == 1 else '🟢 Normal'
        st.write(f"[{row['timestamp']}] Connexion de {row['user']} depuis {row['ip']} => {label}")
        time.sleep(0.3)

# Footer
st.markdown("""
---
*Projet IA - Sécurité SSH - Réalisé avec Streamlit.*
""")
