## Synthèse de la clé USB identifiée

Le fichier `usb-timeline.csv`/`usb-info.csv` révèle un seul périphérique USB de stockage connecté sur la machine analysée, avec une chronologie complète exploitable pour l'US10.

### Identification du périphérique

Le périphérique identifié est une clé **SanDisk Cruzer Blade USB Device**, portant le numéro de série `4C530000281008116284`. Elle a été montée avec la lettre de lecteur **E:\** et le nom de volume **"New Volume"**. Le compte utilisateur associé à cette clé est **user1**.

### Chronologie des événements (03 février 2020)

| Heure (UTC) | Événement |
|---|---|
| 12:12:32.164906 | Première connexion de la clé (First Connected) |
| 12:13:19.368143 | Connexion supplémentaire détectée (Other Connections) |
| 12:44:21.608098 | Dernière connexion enregistrée (Last Connected) |
| 12:45:00.903364 | Retrait de la clé (Last Removed) |

### Constats

- "L'analyse des ruches de registre SYSTEM, SOFTWARE et NTUSER.DAT a permis d'identifier la connexion d'une clé USB SanDisk Cruzer Blade (numéro de série 4C530000281008116284) sur le poste analysé."
- "La première connexion de ce périphérique a été enregistrée le 3 février 2020 à 12:12:32 UTC, correspondant à l'installation initiale du pilote USBSTOR."
- "Une seconde connexion a été détectée à 12:13:19 UTC, suivie d'une session de connexion continue jusqu'à 12:44:21 UTC (dernière connexion enregistrée)."
- "Le retrait de la clé a été journalisé à 12:45:00 UTC, soit environ 33 minutes après la première connexion."
- "La clé a été montée sous la lettre de lecteur E:\ avec le nom de volume 'New Volume', et son usage est associé au compte utilisateur user1."

### Point d'attention

La fenêtre d'activité totale (12:12 à 12:45, soit environ 33 minutes) constitue la base de comparaison avec la fenêtre de fuite supposée du scénario. Si les dates/heures de la fuite documentée tombent dans cet intervalle du 3 février 2020, la concordance est directe et peut être retenue comme preuve. Le champ `OtherDisconnections` étant vide, il n'y a pas eu de déconnexion intermédiaire entre les deux connexions détectées — cohérent avec un usage continu plutôt que des branchements/débranchements répétés.
