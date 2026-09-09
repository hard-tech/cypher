# Rapport Final — Analyse Forensique du Malware « Cypher »

**Projet :** Reverse Engineering & Forensic  
**Date :** 08 septembre 2026

---

## Contexte

Un incident de sécurité a été signalé suite à la suspicion d'un keylogger actif sur un poste Windows. Le fichier suspect `Malware.zip` a été isolé pour analyse. Ce rapport consolide l'ensemble des 10 User Stories (US) du backlog, de la mise en place de l'environnement d'analyse jusqu'à l'identification du vecteur d'infection.

---

## US1 — Mise en place de l'environnement d'analyse

**Objectif :** Préparer un environnement isolé (machine virtuelle) pour exécuter et analyser le malware en toute sécurité.

**Résultat :**
- Une VM Windows a été installée et configurée via VirtualBox.
- Le fichier `Malware.zip` a été transféré dans la VM.
- L'exécution du malware a été observée dans cet environnement contrôlé (copie de fichiers, création du dossier `C:\WindSyst`).

**Statut : Terminé**

---

## US2 — Identification du hash et comparaison avec les bases existantes

**Objectif :** Calculer le hash du fichier suspect et le comparer aux bases de signatures connues (VirusTotal).

**Résultat :**

| Élément | Valeur |
|---|---|
| SHA-256 | `a1af8eeaa7fda7ced591a72c572a12c2298ddb763defaa36ce5b17be1411c2be` |
| Fichier | Malware.zip (8,73 Mo) |
| Détection | **47/69** moteurs antivirus le classent malveillant |
| Famille | `trojan.keylogger/zbxji` |

- Tags comportementaux VirusTotal : `long-sleeps`, `checks-user-input`, `contains-pe`, `detect-debug-environment` → techniques d'évasion classiques.
- Catégories convergentes : **Trojan**, **Adware**, **Spyware** avec capacités de keylogging.

**Statut : Terminé**

---

## US3 — Analyse statique du binaire (FLOSS)

**Objectif :** Extraire les chaînes, imports et indicateurs de compromission par analyse statique du binaire `Res.exe`.

**Résultat :**
- **Compilateur :** MinGW-w64 (GCC), framework Qt5
- **Capacités identifiées :**
  - **Keylogging** : `GetAsyncKeyState`, `GetKeyState`
  - **Persistance** : clé registre `HKCU\...\Run`
  - **Anti-analyse** : détection de sandbox/debug par timing, masquage de fenêtre console
  - **Dropper** : copie de fichiers vers `C:\WindSyst\` (Res.exe, Env.exe, DLLs Qt5/MinGW)
- **Signature :** chaîne `"par le magniquime Hafnium !"` (référence à l'APT Hafnium)
- **IOCs disque :** dépôt dans `C:\WindSyst\`, log dans `c:\WindSyst\log.txt`

**Statut : Terminé**

---

## US4 — Analyse dynamique (observation du comportement à l'exécution)

**Objectif :** Observer le comportement réel du malware lors de son exécution en VM.

**Résultat :**
- Création du répertoire `C:\WindSyst` confirmée.
- Copie réussie de 8 fichiers (DLLs MinGW, DLLs Qt5, Res.exe).
- **Fichiers manquants** (non copiés) : `Qt5Cored.dll`, `Env.exe`, `qminimal.dll`, `qoffscreen.dll`, `qwindows.dll`.
- Bannière `"codé par le magniquime Hafnium !"` affichée au démarrage.
- **Activité réseau :** aucune observée dans ce log.
- **Persistance registre :** non visible dans ce log (nécessite Process Monitor).

**Statut : Terminé**

---

## US5 — Évaluation des risques et recommandations

**Objectif :** Évaluer le niveau de risque et formuler des recommandations de sécurité.

**Résultat :**

### Niveau de risque : ÉLEVÉ

| Impact | Risque | État |
|---|---|---|
| Création d'un répertoire de dépôt | Installation de composants malveillants | Confirmé |
| Copie de plusieurs exécutables/DLL | Déploiement du malware | Confirmé |
| Persistance via le registre | Exécution automatique | À confirmer |
| Communication réseau | C2 / exfiltration | À confirmer |
| Capture clavier | Vol d'informations saisies | À confirmer |

### Recommandations :
1. **Immédiates :** isoler la machine, supprimer `C:\WindSyst`, scan antivirus/EDR complet
2. **Vérification :** Process Monitor / Regshot pour la persistance registre
3. **Réseau :** Wireshark pour détecter les connexions sortantes
4. **Prévention :** MAJ système, EDR, limitation des privilèges, blocage des exécutables non fiables

**Statut : Terminé**

---

## US6 — Acquisition de la mémoire vive

**Objectif :** Effectuer un dump de la RAM et analyser les processus en mémoire avec Volatility.

**Résultat :**
- **Dump :** `memory.raw`, 4,5 Go, SHA-256 `BD0D0CD5...DE816`
- **Outil :** winpmem + Volatility 3

| PID | Processus | Chemin | Durée de vie |
|---|---|---|---|
| 11884 | Res.exe | `...\MalwareLab\VIRUS\Res.exe` | 09:39:58 → 09:40:34 |
| 13648 | Env.exe | `C:\WindSyst\Env.exe` | 09:40:04 → 09:40:13 (9s) |

- `psscan` = `pslist` → pas de processus caché.
- `netscan` vide → Env.exe a crashé avant d'atteindre le code réseau (`smtp.laposte.net:465`).

**Statut : Terminé**

---

## US7 — Acquisition du disque dur

**Objectif :** Réaliser une copie forensique des artefacts disque et vérifier la persistance.

**Résultat :**
- **Image bit-à-bit :** `evidence_volume.vhd` = `evidence_volume.dd.img`, SHA-256 `5B9F6953...EE422` (intégrité vérifiée).
- **Fichiers suspects dans `C:\WindSyst\` :**
  - `Res.exe` (SHA-256 identique à l'échantillon original US2/US3)
  - `Env.exe` (présent mais non fonctionnel — crash Qt)
  - `platforms\` vide (DLLs Qt manquantes)
  - DLLs Qt5 / MinGW (runtimes légitimes embarqués)
- **Persistance confirmée :**
  ```
  HKCU\...\Run\Res = C:\WindSyst\Res.exe
  HKCU\...\Run\Env = C:\WindSyst\Env.exe
  ```

**Statut : Terminé**

---

## US8 — Analyse croisée RAM / disque

**Objectif :** Corréler les données mémoire (US6) et disque (US7) pour reconstruire le scénario d'attaque.

**Résultat :**

### Chronologie reconstituée de l'attaque

| Temps | Heure UTC | Événement |
|---|---|---|
| T+0s | 09:39:58 | Exécution de Res.exe (dropper) → création de `C:\WindSyst`, copie des fichiers |
| T+6s | 09:40:04 | Inscription des clés Run (persistance) + démarrage keylogger + lancement Env.exe |
| T+13s | 09:40:11 | Crash d'Env.exe (plugins Qt manquants dans `platforms\`) |
| T+31s | 09:40:29 | Triage SOC : Res.exe actif, Env.exe absent, aucune connexion réseau |
| T+36s | 09:40:34 | Endiguement : arrêt forcé de Res.exe |
| T+38s | 09:40:36 | Acquisition RAM (winpmem) |

### Conclusions clés :
- **Persistance du keylogger (Res.exe) : OPÉRATIONNELLE** — s'exécute automatiquement à chaque session.
- **Persistance du module réseau (Env.exe) : CONFIGURÉE MAIS NON FONCTIONNELLE** — crash systématique (erreur de packaging par l'attaquant, dossier `platforms\` vide).
- Le silence réseau s'explique par le crash d'Env.exe avant d'atteindre le code d'exfiltration SMTP.

**Statut : Terminé**

---

## US9 — Identification du périphérique USB

**Objectif :** Identifier le périphérique USB ayant servi de vecteur d'infection à partir des ruches de registre.

**Résultat :**

| Élément | Valeur |
|---|---|
| Fabricant | SanDisk |
| Modèle | Cruzer Blade |
| Révision | 1.00 |
| Numéro de série | `4C530000281008116284` |
| Registre | `USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\4C530000281008116284&0` |

- Double vérification : extraction structurée (regipy/parseUSBs) **+** extraction brute (`strings SYSTEM | grep USBSTOR`) → résultats identiques → identification confirmée avec un haut niveau de confiance.

**Statut : Terminé**

---

## US10 — Chronologie d'utilisation de la clé USB

**Objectif :** Reconstituer la timeline de connexion/déconnexion de la clé USB identifiée.

**Résultat :**
- **Périphérique :** SanDisk Cruzer Blade, lettre de lecteur **E:\**, volume "New Volume", utilisateur **user1**.

| Heure (UTC) | Événement |
|---|---|
| 12:12:32 | Première connexion |
| 12:13:19 | Connexion supplémentaire |
| 12:44:21 | Dernière connexion |
| 12:45:00 | Retrait de la clé |

- **Durée totale de connexion :** ~33 minutes (3 février 2020).
- Aucune déconnexion intermédiaire → usage continu.
- Cette fenêtre temporelle est la base de comparaison avec la fenêtre de fuite supposée.

**Statut : Terminé**

---

## Synthèse globale

### IOCs consolidés

| Type | Indicateur |
|---|---|
| Hash SHA-256 (Malware.zip) | `a1af8eeaa7fda7ced591a72c572a12c2298ddb763defaa36ce5b17be1411c2be` |
| Hash SHA-256 (Res.exe) | `49F091ADE48890BFA22D2B455494BE95E52392C478B67E10626222B6AEE37E1E` |
| Répertoire de dépôt | `C:\WindSyst\` |
| Fichier de log keylogger | `C:\WindSyst\log.txt` |
| Clé de persistance | `HKCU\...\Run\Res` et `HKCU\...\Run\Env` |
| Serveur C2 (prévu) | `smtp.laposte.net:465` |
| Clé USB source | SanDisk Cruzer Blade — S/N `4C530000281008116284` |

### Verdict

Le malware `Res.exe` est un **dropper/keylogger** de la famille `trojan.keylogger/zbxji`, compilé avec MinGW-w64 et utilisant le framework Qt5. Il se dépose dans `C:\WindSyst\`, s'inscrit en persistance via le registre (`HKCU\...\Run`), et capture les frappes clavier via `GetAsyncKeyState`. Un module d'exfiltration par email (`Env.exe` → `smtp.laposte.net:465`) était prévu mais **non fonctionnel** en raison d'une erreur de packaging (plugins Qt manquants). Le vecteur d'infection identifié est une clé USB SanDisk Cruzer Blade connectée pendant ~33 minutes le 3 février 2020.

