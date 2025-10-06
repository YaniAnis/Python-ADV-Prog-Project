markdown
# 🛠️ PenTest MultiTools

Plateforme complète de tests d'intrusion avec interface graphique.

## 🚀 Démarrage Rapide (WINDOWS)

### Prérequis Windows
- Docker Desktop avec WSL2 activé
- **VcXsrv** ou **X410** (pour afficher le GUI)
- PowerShell ou CMD

### Installation

1. Cloner le projet:
   ```cmd
   git clone 
   cd pentest-multitools
   ```

2. Configurer l'environnement:
   ```cmd
   setup.bat
   ```

3. **Important - Configurer X Server:**
   - Installer VcXsrv: https://sourceforge.net/projects/vcxsrv/
   - Lancer XLaunch avec ces paramètres:
     * Multiple windows
     * Display number: 0
     * **Cocher "Disable access control"**
     * Finish

4. Construire l'image Docker:
   ```cmd
   docker-compose build
   ```

5. Lancer l'application:
   ```cmd
   docker-compose up
   ```

### Alternative Sans GUI (Mode Console)

Si le GUI pose problème, vous pouvez lancer en mode console:
```cmd
docker-compose run --rm pentest-multitools bash
```

Puis utiliser les outils en ligne de commande.

## 🔧 Utilisation

L'application se lance avec une interface GUI TTKBootstrap comprenant:
- **Network Discovery**: Scan de réseaux avec Scapy/Nmap
- **Port Scanner**: Analyse de ports et services
- **Password Cracker**: Interface pour Hydra/John
- **Web Scanner**: Tests d'applications web
- **Exploit Manager**: Gestion Metasploit

## 📁 Partage avec Collègues

Pour partager le projet:

bash
# Créer une archive
docker save pentest-multitools:latest | gzip > pentest-multitools.tar.gz

# Sur la machine de votre collègue
docker load < pentest-multitools.tar.gz
docker-compose up


## ⚠️ Avertissement

Cet outil est destiné à des fins éducatives et de tests autorisés uniquement.
```