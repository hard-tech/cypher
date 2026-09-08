## US7 — Acquisition du disque dur

### Étapes / commandes
```
robocopy C:\WindSyst ... /E /COPY:DAT        # copie forensique (métadonnées préservées)
reg export HKCU\...\CurrentVersion\Run run-keys.reg
Get-FileHash -Algorithm SHA256 ...           # manifeste d'intégrité par fichier
diskpart: create vdisk evidence_volume.vhd maximum=200 type=fixed
          attach / create partition / format fs=ntfs / assign Z:
robocopy (fichiers ci-dessus) -> Z:\
diskpart: detach vdisk
dd if=evidence_volume.vhd of=evidence_volume.dd.img bs=1M
Get-FileHash evidence_volume.vhd, evidence_volume.dd.img   # comparaison bit-à-bit
```
(pas le disque `C:` entier : volume système actif, 78,7 Go, pas de bloqueur d'écriture → périmètre limité aux artefacts déposés par le malware, réellement imagés bit-à-bit)

### Résultats
- Image bit-à-bit : `evidence_volume.vhd` = `evidence_volume.dd.img`, SHA-256 identique `5B9F6953...EE422` (`evidence/image-integrity.txt`)
- Fichiers suspects (`C:\WindSyst\`, `evidence/windsyst-files.csv` + `hash-manifest.csv`) :

| Fichier | Remarque |
|---|---|
| `Res.exe` (SHA-256 `49F091AD...E37E1E`) | Identique à l'échantillon original US2/US3 |
| `Env.exe` | Copié mais non fonctionnel (crash Qt, cf. US6) |
| `platforms\` | Vide — DLL de plateforme Qt manquantes |
| DLL Qt5 / MinGW | Runtime légitime embarqué |

- Persistance (`evidence/run-keys.reg`) :
```
HKCU\...\Run\Res = C:\WindSyst\Res.exe
HKCU\...\Run\Env = C:\WindSyst\Env.exe
```
