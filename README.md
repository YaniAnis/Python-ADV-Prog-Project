# 🛠️ PenTest MultiTools

Une plateforme complète pour vos tests d'intrusion, équipée d’une interface graphique intuitive.

## 🚀 Démarrage Rapide (WINDOWS)

### Prérequis Windows
- Docker Desktop avec WSL2 activé
- **VcXsrv** ou **X410** (pour l’affichage de l’interface graphique)
- PowerShell ou CMD

### Installation

1. Cloner le dépôt :
git clone
cd pentest-multitools

2. Installer les extension python via la commande :
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt


3. Configurer l’environnement :
setup.bat


3. **Configuration essentielle du X Server :**
- Installer VcXsrv : [https://sourceforge.net/projects/vcxsrv/](https://sourceforge.net/projects/vcxsrv/)
- Lancer XLaunch avec les options suivantes :
  * Multiple windows
  * Display number : 0
  * **Cochez "Disable access control"**
  * Terminez la configuration





## 🔧 Fonctionnalités

L'application propose une interface GUI basée sur TTKBootstrap incluant :

- **Network Discovery** : scans de réseau avec Scapy et Nmap  
- **Port Scanner** : analyse de ports et services ouverts
- **TryHackMe Password Cracker** : outil éducatif pour tests d'authentification
  - Attaques par dictionnaire avec wordlists TryHackMe
  - Démonstrations de force brute éducatives
  - Analyse de patterns de mots de passe
  - Tests de services (SSH/FTP/HTTP) pour CTF
- **Directory Fuzzer** : découverte de répertoires web
- **Subdomain Finder** : reconnaissance de sous-domaines





## ⚠️ Avertissement Important

Cet outil est strictement destiné à un usage éducatif et à des tests d’intrusion autorisés uniquement.
.
