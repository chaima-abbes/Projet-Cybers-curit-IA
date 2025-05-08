# 🔐 Détection d'attaques par force brute sur SSH avec Intelligence Artificielle

Ce projet propose une approche proactive de la sécurité des serveurs SSH en détectant automatiquement les attaques par force brute grâce à un modèle d'intelligence artificielle entraîné sur les journaux d'authentification.

## 📌 Contexte

Les attaques par force brute sont l’une des méthodes les plus répandues pour compromettre des serveurs SSH vulnérables. Elles consistent à tester un grand nombre de combinaisons d'identifiants jusqu’à en trouver une correcte. Une détection intelligente et en temps réel permet de renforcer la sécurité des systèmes critiques.

---

## 🧠 Objectif du projet

Développer un système capable de :
- Identifier les tentatives d'attaques par force brute dans les fichiers logs (`auth.log`).
- Utiliser des algorithmes d’apprentissage automatique pour entraîner un modèle de détection.
- Mettre en place une surveillance en temps réel avec alertes.
- Présenter les résultats dans un dashboard interactif.

---

## ⚙️ Fonctionnalités

- 🔐 Configuration d’un serveur SSH vulnérable (en environnement contrôlé).
- 📄 Génération de trafic : connexions légitimes + attaques par force brute.
- 📈 Prétraitement et extraction de caractéristiques des logs SSH.
- 🤖 Entraînement de modèles IA (ex : Random Forest).
- 🚨 Détection en temps réel des attaques.
- 📊 Dashboard interactif avec visualisation des résultats (via Streamlit).


