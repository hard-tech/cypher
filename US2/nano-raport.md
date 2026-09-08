## Synthèse pour l'US2 — Analyse du hash malveillant

Le hash SHA-256 `a1af8eeaa7fda7ced591a72c572a12c2298ddb763defaa36ce5b17be1411c2be` correspond à un fichier `Malware.zip` (8,73 Mo) déjà connu des bases de VirusTotal, avec un verdict communautaire fortement négatif (score -11) et 47 moteurs antivirus sur 69 le classant comme malveillant.

### Hash calculé

| Type | Valeur |
|---|---|
| SHA-256 | `a1af8eeaa7fda7ced591a72c572a12c2298ddb763defaa36ce5b17be1411c2be` |
| Nom du fichier soumis | Malware.zip |
| Taille | 8,73 Mo |
| Dernière analyse | il y a 9 mois |

### Résultats de détection documentés

47 vendeurs sur 69 flaguent le fichier comme malveillant, avec un label de menace populaire consolidé : `trojan.keylogger/zbxji`. Voici un échantillon représentatif des verdicts par éditeur :

| Éditeur | Verdict |
|---|---|
| Avast / AVG | Win32:Trojan-gen |
| Avira | TR/Spy.KeyLogger.zbxji |
| BitDefender / eScan / GData | Adware.GenericKD.61034276 |
| ESET-NOD32 | Win32/Spy.KeyLogger.RHK Trojan |
| Kaspersky | HEUR:Trojan-Spy.Win32.KeyLogger.gen |
| DrWeb | Trojan.KeyLogger.43162 |
| Cynet | Malicious (score: 99) |
| DeepInstinct | MALICIOUS |

Les tags comportementaux VirusTotal (`long-sleeps`, `checks-user-input`, `contains-pe`, `detect-debug-environment`) indiquent des techniques classiques d'évasion : temporisation d'exécution, vérification d'activité utilisateur avant déclenchement, et détection d'environnement de débogage/sandbox — cohérent avec un comportement de spyware/keylogger conçu pour échapper à l'analyse automatisée. [microsoft](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=TrojanSpy:Win32/Keylogger&threatId=-2147472383)

### Comparaison avec bases existantes

Les catégories de menace attribuées convergent sur trois familles fonctionnelles : **trojan**, **adware** et **spyware**, avec des labels de famille `keylogger` et `zbxji`. Ce triple classement est cohérent avec la définition générique de Malwarebytes pour `Trojan.Keylogger` : capture de frappe clavier, captures d'écran, activité réseau et parfois activation de webcam/micro, données stockées localement ou exfiltrées vers un serveur distant. Le comportement d'accrochage des API de traitement des frappes clavier (keyboard hooking) et de lecture brute du buffer matériel est une technique documentée pour cette catégorie de Trojan-Spy. [malwarebytes](https://www.malwarebytes.com/blog/detections/trojan-keylogger)

### Conclusion

- "Le hash SHA-256 du fichier suspect (`a1af8eeaa7fda7ced591a72c572a12c2298ddb763defaa36ce5b17be1411c2be`) a été calculé et soumis à la base VirusTotal pour comparaison avec les signatures connues."
- "47 des 69 moteurs antivirus interrogés ont classé le fichier comme malveillant, avec un consensus fort sur la famille trojan.keylogger/zbxji."
- "Les catégories de menace identifiées (trojan, adware, spyware) et les tags comportementaux (checks-user-input, detect-debug-environment, long-sleeps) confirment un logiciel espion conçu pour capturer les frappes clavier tout en évitant la détection en environnement d'analyse."
- "La comparaison avec les bases existantes (VirusTotal) permet de confirmer avec un haut niveau de confiance que le fichier `Malware.zip` constitue la charge malveillante à l'origine du keylogging suspecté dans l'incident."
