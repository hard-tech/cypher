## 1. Description des impacts

L’analyse dynamique de `Res.exe` met en évidence plusieurs comportements présentant un risque pour la machine.

### Création et dépôt de fichiers

Le malware tente de créer le répertoire `C:\WindSyst` afin d'y déposer ses composants. Plusieurs fichiers ont effectivement été copiés avec succès dans ce répertoire, notamment `Res.exe`, des DLL MinGW ainsi que plusieurs DLL Qt5.

Cette activité peut permettre au malware de s'installer dans un emplacement dédié et de conserver ses différents composants sur la machine.

### Risque de persistance

L'analyse statique avait identifié une possible modification de la clé de registre `HKCU\...\Run`. Cependant, cette modification n'a pas pu être confirmée avec le log dynamique disponible. Une analyse avec Regshot ou Process Monitor serait nécessaire pour confirmer cette persistance.

Si elle était confirmée, cette technique permettrait au malware de se relancer automatiquement lors de l'ouverture de session de l'utilisateur.

### Capacité réseau potentielle

Aucune communication réseau n'a été observée pendant le test. Cependant, `Qt5Network.dll` est présente parmi les composants copiés, ce qui indique une capacité réseau potentielle du programme. Cette capacité pourrait notamment être utilisée pour communiquer avec un serveur distant, exfiltrer des données ou télécharger d'autres composants. Ces comportements restent toutefois à confirmer.

### Risque lié à la capture clavier

L'analyse statique a également identifié l'utilisation potentielle de fonctions telles que `GetAsyncKeyState` et `GetKeyState`. Cela peut correspondre à une capacité de surveillance des frappes clavier. Le comportement n'a cependant pas été observé dans le log fourni et nécessiterait un test comportemental spécifique pour être confirmé.

### Exécution de processus

Le binaire utilise des commandes `mkdir` et `XCOPY`, ce qui implique potentiellement l'utilisation de `cmd.exe` et `xcopy.exe`. La création effective de ces processus enfants n'est toutefois pas directement confirmée par le log.

---

## 2. Niveau de risque évalué

### **Niveau de risque : ÉLEVÉ**

Le niveau de risque est évalué comme **élevé**, principalement en raison de la combinaison de plusieurs comportements potentiellement malveillants :

| Impact                             | Risque                                  | État            |
| ---------------------------------- | --------------------------------------- | --------------- |
| Création d'un répertoire de dépôt  | Installation de composants malveillants | **Confirmé**    |
| Copie de plusieurs exécutables/DLL | Déploiement du malware sur la machine   | **Confirmé**    |
| Persistance via le registre        | Exécution automatique                   | **À confirmer** |
| Communication réseau               | C2, exfiltration ou téléchargement      | **À confirmer** |
| Capture clavier                    | Vol potentiel d'informations saisies    | **À confirmer** |
| Exécution de processus enfants     | Exécution de commandes système          | **À confirmer** |

Le risque pourrait être considéré comme **critique** si les mécanismes de persistance, de communication réseau et de capture clavier étaient confirmés.

---

## 3. Recommandations de sécurité

Afin de limiter l'impact de ce malware, plusieurs mesures peuvent être mises en place.

### Mesures immédiates

* Isoler la machine potentiellement infectée du réseau.
* Ne pas exécuter le malware sur une machine de production.
* Supprimer les fichiers malveillants identifiés, notamment le contenu de `C:\WindSyst`, après conservation des éléments nécessaires à l'analyse.
* Effectuer une analyse antivirus/EDR complète de la machine.

### Vérification de la persistance

* Utiliser **Process Monitor** ou **Regshot** pour surveiller les modifications du registre.
* Vérifier particulièrement la clé `HKCU\...\Run`.
* Contrôler les tâches planifiées, services et autres mécanismes permettant un démarrage automatique.

### Surveillance réseau

* Utiliser **Wireshark**, un proxy d'analyse ou un environnement réseau simulé afin d'identifier d'éventuelles communications sortantes.
* Bloquer les connexions réseau non nécessaires depuis une machine d'analyse.
* Surveiller les connexions vers des domaines ou adresses IP inconnus.

### Prévention

* Maintenir Windows et les logiciels à jour.
* Utiliser un antivirus/EDR correctement configuré.
* Limiter les privilèges des utilisateurs.
* Empêcher l'exécution de fichiers provenant de sources non fiables.
* Mettre en place une surveillance des créations et exécutions de fichiers inhabituelles.

## Conclusion

L'analyse dynamique confirme que `Res.exe` possède un comportement de type **dropper** : il crée le répertoire `C:\WindSyst` et y dépose plusieurs composants nécessaires à son fonctionnement.

Le risque est donc évalué à **ÉLEVÉ**. Certains impacts supplémentaires, notamment la persistance dans le registre, les communications réseau et la capture clavier, restent à confirmer. Une analyse complémentaire avec Process Monitor, Regshot et Wireshark permettrait de déterminer précisément l'étendue des capacités du malware.
