FROM kalilinux/kali-rolling:latest

# Éviter les prompts interactifs
ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:0

# Mettre à jour et installer les dépendances système
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-tk \
    nmap \
    hydra \
    john \
    metasploit-framework \
    gobuster \
    masscan \
    nikto \
    sqlmap \
    git \
    curl \
    wget \
    net-tools \
    iputils-ping \
    tcpdump \
    wireshark-common \
    x11-apps \
    xvfb \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    python3-dev \
    gcc \
    g++ \
    build-essential \
    libjpeg-dev \
    zlib1g-dev \
    libfreetype6-dev \
    liblcms2-dev \

    && rm -rf /var/lib/apt/lists/*

# Créer le répertoire de travail
WORKDIR /app

# Copier les fichiers de requirements
COPY requirements.txt .

# Installer pip et setuptools d'abord
RUN pip3 install --no-cache-dir --break-system-packages --upgrade pip setuptools wheel

# Installer les dépendances Python en plusieurs étapes

RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt


# Copier le code de l'application
COPY app/ ./app/
COPY scripts/ ./scripts/

# Rendre les scripts exécutables
RUN chmod +x scripts/*.sh

# Créer les répertoires nécessaires
RUN mkdir -p /app/data/wordlists /app/data/reports /app/data/configs

# Télécharger des wordlists populaires
RUN wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt \
    -O /app/data/wordlists/passwords.txt 2>/dev/null || echo "Wordlist download skipped"

# Initialiser la base de données Metasploit (optionnel)
RUN service postgresql start && \
    msfdb init || true && \
    service postgresql stop

# Exposer le port pour l'interface web (optionnel)
EXPOSE 8080

# Variable d'environnement pour le GUI
ENV PYTHONUNBUFFERED=1

# Point d'entrée
CMD ["python3", "app/main.py"]