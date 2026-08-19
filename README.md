# Cyber Security Scanner

Outil Python d'analyse de sécurité d'une cible autorisée.

## Fonctionnalités

- Résolution DNS de la cible
- Scan TCP des ports 8000 à 8020
- Détection des services HTTP
- Récupération des en-têtes HTTP
- Vérification de headers de sécurité
- Évaluation simple du niveau de risque
- Génération d'un rapport `scan_report.txt`

## Technologies

- Python
- TCP/IP
- HTTP
- Linux / WSL
- Git

## Utilisation

```bash
python3 scanner.py 127.0.0.1
```
Le scanner doit être utilisé uniquement sur des systèmes que vous êtes autorisé à analyser.

## Rapport

Après le scan, un fichier `scan_report.txt` est généré avec les résultats.

## État

Projet finalisé — version 1.0.
