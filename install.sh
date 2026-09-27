#!/usr/bin/env bash
# ============================================
# BURP-LIKE WEB v2.0
# Script d'installation automatique
# ============================================

set -e

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[X]${NC} $1"; }

echo ""
cat << "EOF"

  ____                  _         _ _
 | __ ) _   _ _ __ _ __| |       | (_)_ __
 |  _ \| | | | '__| '_ \ |_____  | | | '_ \
 | |_) | |_| | |  | |_) |______| | | | | | |
 |____/ \__,_|_|  | .__/          |_|_|_| |_|
                  |_|

      BURP-LIKE WEB v2.0 — Installation
      Usage educatif / CTF / pentest autorise

EOF
echo ""

# 1. Python
log "Verification de Python..."
if ! command -v python3 &> /dev/null; then
    err "Python3 manquant."
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv
else
    ok "Python3 : $(python3 --version 2>&1 | awk '{print $2}')"
fi

# 2. venv
log "Verification de venv..."
if ! python3 -c "import venv" &> /dev/null; then
    sudo apt install -y python3-venv
fi
ok "venv disponible"

# 3. Créer/activer le venv
if [ -d ".venv" ]; then
    VENV_DIR=".venv"
    warn "Dossier '.venv' detecte, reutilisation..."
elif [ -d "venv" ]; then
    VENV_DIR="venv"
    warn "Dossier 'venv' detecte, reutilisation..."
else
    VENV_DIR=".venv"
    log "Creation du venv dans '$VENV_DIR'..."
    python3 -m venv "$VENV_DIR"
    ok "Venv cree"
fi

log "Activation de ./$VENV_DIR ..."
source "$VENV_DIR/bin/activate"
ok "Python actif : $(which python3)"

# 4. pip
log "Mise a jour de pip..."
python3 -m pip install --upgrade pip setuptools wheel 2>&1 | tail -1
ok "pip a jour"

# 5. Dépendances
log "Installation des dependances..."
if [ -f "requirements.txt" ]; then
    python3 -m pip install -r requirements.txt
    ok "Dependances installees"
else
    warn "requirements.txt absent, installation manuelle..."
    python3 -m pip install Flask mitmproxy requests urllib3
    ok "Dependances installees manuellement"
fi

# 6. Vérification
log "Verification des imports..."
python3 -c "
import sys
ok = True
try:
    import flask; print('  Flask:', flask.__version__)
except: print('  Flask: MANQUANT'); ok = False
try:
    import mitmproxy; print('  mitmproxy: OK')
except: print('  mitmproxy: MANQUANT'); ok = False
try:
    import requests; print('  requests:', requests.__version__)
except: print('  requests: MANQUANT'); ok = False
sys.exit(0 if ok else 1)
" && ok "Tous les imports OK" || warn "Certains imports manquants"

# 7. Dossiers
log "Preparation des dossiers..."
mkdir -p ~/.burp_like_web
mkdir -p ~/.mitmproxy
ok "Dossiers prets"

# 8. Fichier principal
MAIN_FILE=""
for f in burp_like_web.py burp_like.py Burp_like.py; do
    if [ -f "$f" ]; then
        MAIN_FILE="$f"
        break
    fi
done

if [ -n "$MAIN_FILE" ]; then
    ok "Fichier principal : $MAIN_FILE"
else
    warn "Aucun fichier burp_like_web.py detecte"
fi

# 9. Résumé
echo ""
echo -e "${GREEN}========================================================${NC}"
echo -e "${GREEN}  INSTALLATION TERMINEE${NC}"
echo -e "${GREEN}========================================================${NC}"
echo ""
echo -e "  ${BOLD}Prochaines etapes :${NC}"
echo ""
echo -e "  1. Activer le venv :"
echo -e "     ${CYAN}source $VENV_DIR/bin/activate${NC}"
echo ""
echo -e "  2. Lancer Burp-Like Web :"
if [ -n "$MAIN_FILE" ]; then
    echo -e "     ${CYAN}python3 $MAIN_FILE${NC}"
else
    echo -e "     ${CYAN}python3 burp_like_web.py${NC}"
fi
echo ""
echo -e "  3. Ouvrir dans le navigateur :"
echo -e "     ${CYAN}http://127.0.0.1:5000${NC}"
echo ""
echo -e "  4. Configurer le proxy de ton navigateur :"
echo -e "     ${CYAN}127.0.0.1:8080${NC}"
echo ""
echo -e "  5. Installer le CA mitmproxy (pour HTTPS) :"
echo -e "     ${CYAN}CA dans ~/.mitmproxy/mitmproxy-ca-cert.pem${NC}"
echo ""
echo -e "  ${YELLOW}Rappel legal :${NC}"
echo -e "     Usage educatif / CTF / pentest AUTORISE uniquement."
echo ""
echo -e "${GREEN}========================================================${NC}"
echo ""