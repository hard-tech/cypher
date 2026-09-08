## US6 — Acquisition mémoire vive

### Étapes / commandes
```
winpmem_mini_x64_rc2.exe memory.raw          # dump RAM physique (winpmem)
Get-FileHash -Algorithm SHA256 memory.raw    # hash d'intégrité
pip install volatility3                      # analyse hors-ligne
vol -f memory.raw windows.info               # vérifie l'intégrité du dump
vol -f memory.raw windows.pslist / pstree / psscan
vol -f memory.raw windows.netscan
```

### Résultats
- Dump : `memory.raw`, 4,5 Go (4 831 838 208 o), SHA-256 `BD0D0CD5...DE816` — `windows.info` retrouve les symboles noyau → dump complet et exploitable
- Processus actifs :

| PID | Processus | Chemin | Créé→Terminé (UTC) |
|---|---|---|---|
| 11884 | Res.exe | `...\MalwareLab\VIRUS\Res.exe` | 09:39:58 → 09:40:34 |
| 13648 | Env.exe | `C:\WindSyst\Env.exe` | 09:40:04 → 09:40:13 |

(psscan = pslist, pas de processus caché)
- Réseau : `windows.netscan` vide (processus déjà terminés) ; triage live = aucune connexion vers `smtp.laposte.net:465` (Env.exe a crashé avant d'atteindre le code réseau)
