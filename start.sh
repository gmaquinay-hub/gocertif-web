#!/bin/bash
# GoCertif Web — Script de démarrage
# Usage: ./start.sh

cd "$(dirname "$0")"

echo "=========================================="
echo "  GoCertif Web — HAS V2025"
echo "=========================================="

# Vérifier Python 3
if ! command -v python3 &>/dev/null; then
    echo "❌ Python 3 est requis. Installez-le depuis https://www.python.org"
    exit 1
fi

# Installer les dépendances si nécessaire
echo "➜ Vérification des dépendances..."
python3 -c "import tornado" 2>/dev/null || pip3 install tornado
python3 -c "import openpyxl" 2>/dev/null || pip3 install openpyxl
python3 -c "import reportlab" 2>/dev/null || pip3 install reportlab

# Ouvrir le navigateur automatiquement (si possible)
URL="http://localhost:5050"
if command -v open &>/dev/null; then
    sleep 1 && open "$URL" &
elif command -v xdg-open &>/dev/null; then
    sleep 1 && xdg-open "$URL" &
elif command -v start &>/dev/null; then
    sleep 1 && start "$URL" &
fi

echo "➜ Lancement du serveur sur $URL"
echo "  Ctrl+C pour arrêter"
echo ""

python3 app.py
