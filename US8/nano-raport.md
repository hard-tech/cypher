# US8 — Analyse croisée RAM / disque

**Rôle SOC :** Analyste SOC  
**Objectif :** Corréler les données de la mémoire vive (US6) et du disque dur (US7) afin de reconstruire un scénario d'attaque cohérent et prouver la persistance du malware.

---

## 1. Méthodologie et sources de données

L'analyse croisée repose sur la confrontation directe entre les artefacts volatils capturés en RAM et les artefacts persistants extraits du disque :

| Source | Support / Éléments analysés | Preuves associées |
|---|---|---|
| **Mémoire (US6)** | Dump physique `memory.raw` (4,5 Go, SHA-256 `BD0D0CD5...DE816`), analysé via **Volatility 3** (`windows.pstree`, `windows.psscan`, `windows.netscan`, `windows.info`) + triage live (`netconnections.csv`, `process-list.csv`) + journal Application Windows (WER APPCRASH). | `US6/evidence/volatility/*`, `US6/evidence/netconnections.csv` |
| **Disque (US7)** | Copie forensique du répertoire `C:\WindSyst\`, export registre `run-keys.reg`, image disque bit-à-bit `evidence_volume.dd.img` (SHA-256 `5B9F6953...EE422`) et manifeste d'intégrité `hash-manifest.csv`. | `US7/evidence/hash-manifest.csv`, `US7/evidence/windsyst-files.csv`, `US7/evidence/run-keys.reg`, `US7/evidence/image-integrity.txt` |

---

## 2. Correspondance processus mémoire ↔ fichiers disque

### Tableau de corrélation forensique

| Processus mémoire (US6) | PID / PPID | Horodatage RAM (UTC) | Fichier disque associé (US7) | Taille / Hash SHA-256 | Statut de corrélation & Analyse |
|---|---|---|---|---|---|
| `Res.exe` | **11884** / 1020 | **09:39:58** $\rightarrow$ **09:40:34** (actif au triage 09:40:29) | `C:\WindSyst\Res.exe` & `MalwareLab\VIRUS\Res.exe` | 25 088 octets <br>`49F091ADE48890BFA22D2B455494BE95E52392C478B67E10626222B6AEE37E1E` | **MATCH PARFAIT** — Le hash de l'exécutable sur disque est rigoureusement identique à l'échantillon initial (US2/US3). En mémoire, le processus a agi en tant que **dropper** (création de `C:\WindSyst`, copie des DLLs) puis **keylogger** actif (`GetAsyncKeyState`). |
| `Env.exe` | **13648** / 1020 | **09:40:04** $\rightarrow$ **09:40:13** (terminé après 9s) | `C:\WindSyst\Env.exe` | 53 248 octets <br>(présent dans l'image VHD/DD) | **CORRÉLATION EXPLICATIVE** — Fichier intact sur disque mais exécution avortée en RAM après 9s (erreur WER APPCRASH `0x40000015` dans `Qt5Core.dll`). L'analyse disque révèle que le dossier `C:\WindSyst\platforms\` est **vide**, provoquant un arrêt critique Qt avant l'ouverture de la connexion réseau. |
| `reg.exe` | **4572** / 1020 | **09:40:04** $\rightarrow$ **09:40:04** (durée < 1s) | `C:\Windows\System32\reg.exe` | Binaire système légitime | **TRACE DE PERSISTANCE** — Processus repéré dans `windows.psscan`. Il a été invoqué pour inscrire les clés de démarrage automatique dans le registre utilisateur (`run-keys.reg`). |
| *(Dossier)* | N/A | N/A | `C:\WindSyst\platforms\` | Dossier vide (0 octet, créé à 09:39:59 UTC) | **CAUSE PHYSIQUE DU CRASH** — L'absence sur disque des plugins graphiques Qt (`qwindows.dll`, `qminimal.dll`) est la cause directe du plantage de `Env.exe` observé en mémoire. |
| *(DLLs support)* | N/A | Chargées par PID 11884 & 13648 | `C:\WindSyst\Qt5*.dll` <br>`C:\WindSyst\lib*.dll` | 7 bibliothèques répertoriées dans `hash-manifest.csv` | **DÉPENDANCES DISQUE** — Runtimes MinGW et bibliothèques Qt5 déposés par `Res.exe` pour fournir l'environnement d'exécution aux deux binaires malveillants. |

### Analyse technique croisée

1. **Intégrité et identité de `Res.exe` :**
   Le processus observé en mémoire sous le PID 11884 a été exécuté depuis le répertoire de test, mais le fichier identique a été copié sur le disque dans `C:\WindSyst\Res.exe`. Son hash SHA-256 (`49F091AD...E37E1E`) correspond trait pour trait à celui documenté lors de la reconnaissance (US2) et de l'analyse statique (US3). Aucune altération n'a eu lieu lors du déploiement.

2. **Élucidation du silence réseau grâce à la corrélation RAM-Disque :**
   L'analyse de la mémoire vive révélait que `windows.netscan` ne montrait aucune connexion sortante vers `smtp.laposte.net:465` (US6). La corrélation avec les preuves disque résout complètement cette énigme :
   - Le journal d'événements Application Windows (artefact disque) consigne à 09:40:11 UTC un plantage d'`Env.exe` avec le code d'exception `0x40000015` (`STATUS_FATAL_APP_EXIT`) dans `Qt5Core.dll`.
   - L'inventaire disque (`windsyst-files.csv`) confirme que le sous-répertoire `C:\WindSyst\platforms\` a bien été créé lors de l'infection mais qu'il est resté **vide** (les plugins `qwindows.dll` / `qminimal.dll` n'étaient pas présents dans l'archive originale).
   - En conséquence, le framework Qt n'a pas pu initialiser la couche graphique minimale et a invoqué `qFatal()`, provoquant la mort immédiate du processus `Env.exe` (ExitTime à 09:40:13 UTC, soit 9 secondes de vie) bien avant qu'il ne puisse atteindre les routines d'exfiltration SMTP codées dans `Qt5Network.dll`.

---

## 3. Détection et validation de la persistance

### Chaîne de preuve complète (Registre $\rightarrow$ Disque $\rightarrow$ Mémoire)

La corrélation démontre la présence d'une chaîne de persistance formellement vérifiée :

```
[ REGISTRE (US7) ]
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
  ├─ "Res" = "C:\WindSyst\Res.exe"
  └─ "Env" = "C:\WindSyst\Env.exe"
            │
            ▼
[ DISQUE DUR (US7) ]
C:\WindSyst\
  ├─ Res.exe  (Présent, 25 088 o, Hash SHA-256 intact)
  ├─ Env.exe  (Présent, 53 248 o)
  └─ DLLs MinGW / Qt5 (Présentes et opérationnelles)
            │
            ▼
[ MÉMOIRE VIVE (US6) ]
  ├─ PID 11884 (Res.exe) : Exécuté avec succès, écoute clavier active
  └─ PID 13648 (Env.exe) : Démarré puis crashé par manque de dépendance
```

### Évaluation de l'efficacité de la persistance

- **Persistance du Keylogger (`Res.exe`) : PLEINEMENT OPÉRATIONNELLE.**
  Le binaire existe au chemin exact configuré dans la clé `Run`, possède toutes ses DLLs de support dans son répertoire d'exécution (`C:\WindSyst`), et fonctionne sans dépendre de plugin graphique. À chaque ouverture de session de l'utilisateur, `Res.exe` s'exécute automatiquement en tâche de fond pour intercepter les frappes du clavier.
- **Persistance du Module d'Exfiltration (`Env.exe`) : CONFIGURÉE MAIS NON FONCTIONNELLE.**
  L'entrée de registre est bien en place et le fichier existe sur disque. Toutefois, à chaque tentative de démarrage au reboot, `Env.exe` plantera systématiquement en quelques secondes en raison de l'absence du répertoire `platforms\qwindows.dll`. L'attaquant a correctement configuré son mécanisme de persistance mais a commis une erreur de packaging dans la distribution de ses dépendances Qt.

---

## 4. Reconstruction du scénario d'attaque complet

Le croisement des horodatages mémoire, disque et système permet de retracer l'attaque avec une précision absolue :

```
Temps Relatif | Heure UTC   | Événement & Interprétation technique
==============|=============|=============================================================================
T + 0s        | 09:39:58    | EXÉCUTION DU DROPPER : Res.exe est lancé (PID 11884).
              |             | -> Création immédiate du répertoire de dépôt C:\WindSyst (09:39:59 UTC).
              |             | -> Création du dossier C:\WindSyst\platforms\ (laissé vide).
              |             | -> Déploiement par copie de Res.exe, Env.exe et des 7 DLLs MinGW/Qt5.
--------------|-------------|-----------------------------------------------------------------------------
T + 6s        | 09:40:04    | PERSISTANCE & MODULE RÉSEAU :
              |             | -> Inscription des clés Run via reg.exe (PID 4572) : Run\Res et Run\Env.
              |             | -> Démarrage de la boucle d'écoute clavier de Res.exe (GetAsyncKeyState).
              |             | -> Lancement du module d'exfiltration Env.exe (PID 13648).
--------------|-------------|-----------------------------------------------------------------------------
T + 13s       | 09:40:11    | CRASH DU MODULE RÉSEAU :
              |             | -> Échec du chargement du plugin Qt platform (platforms\ vide).
              |             | -> WER consigne l'événement APPCRASH dans Qt5Core.dll (0x40000015).
--------------|-------------|-----------------------------------------------------------------------------
T + 15s       | 09:40:13    | SORTIE MÉMOIRE D'ENV.EXE : Le processus 13648 disparaît de la RAM.
--------------|-------------|-----------------------------------------------------------------------------
T + 31s       | 09:40:29    | TRIAGE LIVE SOC :
              |             | -> Res.exe (PID 11884) est détecté actif en mémoire.
              |             | -> Env.exe est déjà absent. Aucune connexion sortante sur le port 465.
--------------|-------------|-----------------------------------------------------------------------------
T + 36s       | 09:40:34    | ENDIGUEMENT : Interruption forcée du processus Res.exe (PID 11884).
--------------|-------------|-----------------------------------------------------------------------------
T + 38s       | 09:40:36    | FORENSIC RAM : Lancement de winpmem (PID 13568) et capture de memory.raw.
--------------|-------------|-----------------------------------------------------------------------------
T + 73s       | 09:41:11    | FORENSIC DISQUE : Copie forensique de C:\WindSyst, export du registre,
              |             | création du volume VHD et acquisition bit-à-bit evidence_volume.dd.img.
```

### Concordance avec les étapes de la Kill Chain et les US précédentes

- **Reconnaissance & Signature (US2) :** Le hash de `Res.exe` confirme l'appartenance à la famille de spyware/keylogger `zbxji`.
- **Analyse Statique (US3) :** La fonction d'installation et de persistance découverte dans `Res.exe` s'est exécutée exactement comme prédit (création de `C:\WindSyst`, écriture de la clé `Run`, écriture dans `log.txt`).
- **Analyse Dynamique (US4) :** L'absence des DLLs `platforms\` constatée lors des copies XCOPY explique physiquement l'échec de la couche réseau.
- **Évaluation des Risques (US5) :** Les hypothèses de persistance et de capture clavier sont désormais formellement **confirmées** par les preuves forensiques RAM et disque.

---

## 5. Indicateurs de Compromission (IOC) consolidés

| Type | Indicateur | Description |
|---|---|---|
| **Hash SHA-256** | `49F091ADE48890BFA22D2B455494BE95E52392C478B67E10626222B6AEE37E1E` | Binaire `Res.exe` (Dropper & Keylogger) |
| **Hash SHA-256** | `BD0D0CD56C6E535807967EF7405197AF9F5FE66BE63643B7725D6D71421DE816` | Dump mémoire physique brute `memory.raw` |
| **Hash SHA-256** | `5B9F6953643A9C2FE01F03DCF8F96E7B40D026C25CDE04006EB54DF8001EE422` | Image forensique bit-à-bit `evidence_volume.dd.img` |
| **Chemin Disque** | `C:\WindSyst\` | Répertoire de dépôt racine du malware |
| **Chemin Disque** | `C:\WindSyst\Res.exe` & `C:\WindSyst\Env.exe` | Exécutables malveillants déployés |
| **Chemin Disque** | `C:\WindSyst\log.txt` | Fichier local de capture des frappes clavier |
| **Clé Registre** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Res` | Persistance active du keylogger (`C:\WindSyst\Res.exe`) |
| **Clé Registre** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Env` | Persistance dormante du module réseau (`C:\WindSyst\Env.exe`) |
| **Réseau (prévu)**| `smtp.laposte.net:465` (TCP / TLS) | Serveur C2 d'exfiltration ciblé par le code d'`Env.exe` |
