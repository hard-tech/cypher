==================================================================
RAPPORT D'ANALYSE STATIQUE - FLOSS (FLARE FLOSS v3.1.1-0-g3cd3ee6)
==================================================================

Fichier analysé   : Res.exe
Chemin d'origine  : C:\Users\vboxuser\Downloads\Malware (3)\VIRUS\Res.exe
Langage détecté   : inconnu
Compilateur       : MinGW-w64 (GCC 4.9.3 / 5.3.0, i686-posix-dwarf-rev0)
Framework         : Qt5

Chaînes statiques extraites : 231 (5767 caractères)
Chaînes UTF-16LE             : 0
Stack strings                : 0
Tight strings                : 0
Chaînes décodées              : 1 ("[DEL]")

------------------------------------------------------------------
1. FONCTIONS PRINCIPALES IDENTIFIEES (IMPORTS API)
------------------------------------------------------------------

Persistance / exécution système :
  - GetModuleHandleA, GetProcAddress, LoadLibraryA, FreeLibrary
      -> résolution dynamique de fonctions (évasion détection statique)
  - system()
      -> exécution de commandes shell (mkdir / XCOPY observés)

Anti-analyse / anti-debug :
  - SetUnhandledExceptionFilter, UnhandledExceptionFilter
  - QueryPerformanceCounter, GetTickCount
      -> techniques de détection de sandbox/debug par timing
  - GetConsoleWindow, ShowWindow
      -> manipulation / masquage de fenêtre console
  - TerminateProcess, GetCurrentProcess, GetCurrentProcessId,
    GetCurrentThreadId, GetLastError

Capture d'entrée utilisateur (KEYLOGGING) :
  - GetAsyncKeyState
  - GetKeyState

Threading / concurrence :
  - InitializeCriticalSection, EnterCriticalSection,
    LeaveCriticalSection, DeleteCriticalSection, TlsGetValue,
    pthread_equal
  - Symboles C++ std::thread démanglés (_ZNSt6thread...)
      -> usage de threads C++11 (implémentation MinGW)

Registre / configuration (Qt) :
  - QSettings::setValue, QCoreApplication::exec
      -> stockage de configuration, potentiellement lié au
         registre Windows via l'API Qt

------------------------------------------------------------------
2. IMPORTS / DLL ET SECTIONS ANALYSEES
------------------------------------------------------------------

DLL importées :
  - KERNEL32.dll        (API système bas niveau)
  - USER32.dll           (clavier, fenêtres - GetAsyncKeyState)
  - msvcrt.dll            (runtime C)
  - libgcc_s_dw2-1.dll   (runtime GCC/MinGW)
  - libstdc++-6.dll      (runtime C++ MinGW)
  - libwinpthread-1.dll  (threads POSIX pour Windows)
  - Qt5Core.dll           (framework applicatif Qt5)

Sections PE repérées (structure standard MinGW) :
  .text  .data  .rdata  .eh_frame  .bss  .idata  .CRT  .tls
  (pas de section custom/packée visible dans ce dump de strings)

Chaîne décodée obfusquée :
  "[DEL]"  -> probablement construite/assemblée en mémoire au
              lieu d'être stockée en clair

Chaîne suspecte notable :
  "par le magniquime Hafnium !"
  -> référence probable à l'acteur de menace "Hafnium"
     (APT associé aux exploitations Microsoft Exchange),
     possible signature de campagne ou marquage de l'auteur

------------------------------------------------------------------
3. INDICATEURS DE COMPROMISSION (IOC)
------------------------------------------------------------------

Dossier de dépôt :
  C:\WindSyst\

Fichiers déposés dans C:\WindSyst\ :
  - Res.exe
  - Env.exe
  - libgcc_s_dw2-1.dll
  - libstdc++-6.dll
  - libwinpthread-1.dll
  - Qt5Cored.dll
  - Qt5Widgets.dll
  - Qt5Network.dll
  - Qt5Gui.dll
  - Qt5Core.dll

Sous-dossier plateforme Qt : C:\WindSyst\platforms\
  - qminimal.dll
  - qoffscreen.dll
  - qwindows.dll

Clé de persistance (registre) :
  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

Valeurs de Run probables :
  - C:\WindSyst\Res.exe
  - C:\WindSyst\Env.exe

Fichier de log :
  c:\WindSyst\log.txt

Chemin d'origine (poste d'analyse, PAS un IOC réseau) :
  C:\Users\vboxuser\Downloads\Malware (3)\VIRUS\Res.exe

Chaîne de signature/marquage :
  Hafnium

------------------------------------------------------------------
4. SYNTHESE COMPORTEMENTALE
------------------------------------------------------------------

Le binaire copie un ensemble de DLL Qt5 ainsi que deux exécutables
(Res.exe et Env.exe) dans le répertoire C:\WindSyst, s'installe en
persistance via la clé de registre Run (HKCU), journalise son
activité dans log.txt, et embarque des capacités de capture
clavier (GetAsyncKeyState / GetKeyState).

Profil cohérent avec un DROPPER / STEALER doté d'un module
KEYLOGGER, packagé avec une interface graphique Qt5 et compilé
via la chaîne d'outils MinGW-w64.

Recommandation : analyser également Env.exe et effectuer une
analyse dynamique (sandbox) pour confirmer les communications
réseau, la persistance effective, et les données exfiltrées.

==================================================================
Fin du rapport
==================================================================