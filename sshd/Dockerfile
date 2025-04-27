# Utiliser une image Python légère
FROM python:3.11-slim

# Définir le dossier de travail
WORKDIR /opt/potdemiel/sshd

# Copier les fichiers du projet
COPY . .

# Installer les dépendances nécessaires
RUN pip install --no-cache-dir paramiko python-dotenv

# Exposer le port SSH (sera relié via docker-compose)
EXPOSE 22

# Commande de lancement
CMD ["python3", "app.py"]
