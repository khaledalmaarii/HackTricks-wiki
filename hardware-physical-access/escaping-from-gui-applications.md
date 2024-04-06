<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>


# Verifica delle possibili azioni all'interno dell'applicazione GUI

I **Dialoghi comuni** sono quelle opzioni di **salvataggio di un file**, **apertura di un file**, selezione di un carattere, di un colore... La maggior parte di essi offrirà una funzionalità completa di Esplora risorse. Ciò significa che sarà possibile accedere alle funzionalità di Esplora risorse se si può accedere a queste opzioni:

* Chiudi/Chiudi come
* Apri/Apri con
* Stampa
* Esporta/Importa
* Cerca
* Scansione

Dovresti verificare se puoi:

* Modificare o creare nuovi file
* Creare collegamenti simbolici
* Ottenere accesso a aree restritte
* Eseguire altre applicazioni

## Esecuzione di comandi

Forse **utilizzando l'opzione `Apri con`** puoi aprire/eseguire una sorta di shell.

### Windows

Ad esempio _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ trova altri binari che possono essere utilizzati per eseguire comandi (e compiere azioni impreviste) qui: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX __

_bash, sh, zsh..._ Altro qui: [https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## Eludere le restrizioni del percorso

* **Variabili d'ambiente**: Ci sono molte variabili d'ambiente che puntano a un determinato percorso
* **Altri protocolli**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
* **Collegamenti simbolici**
* **Scorciatoie**: CTRL+N (apri nuova sessione), CTRL+R (Esegui comandi), CTRL+SHIFT+ESC (Task Manager),  Windows+E (apri Esplora risorse), CTRL-B, CTRL-I (Preferiti), CTRL-H (Cronologia), CTRL-L, CTRL-O (File/Apri dialogo), CTRL-P (Dialogo di stampa), CTRL-S (Salva come)
* Menu amministrativo nascosto: CTRL-ALT-F8, CTRL-ESC-F9
* **URI della shell**: _shell:Strumenti di amministrazione, shell:Libreria documenti, shell:Biblioteche, shell:Profili utente, shell:Personale, shell:Cartella di ricerca, shell:Sistema, shell:Cartelle di rete, shell:Invia a, shell:Profili utenti, shell:Strumenti di amministrazione comuni, shell:Risorse del computer, shell:Cartella Internet_
* **Percorsi UNC**: Percorsi per connettersi a cartelle condivise. Dovresti provare a connetterti a C$ della macchina locale ("\\\127.0.0.1\c$\Windows\System32")
* **Altri percorsi UNC:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

## Scarica i tuoi binari

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Esplora risorse: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Editor del registro di sistema: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## Accesso al filesystem dal browser

| PERCORSO                | PERCORSO              | PERCORSO               | PERCORSO                |
| ----------------------- | --------------------- | ---------------------- | ----------------------- |
| File:/C:/windows        | File:/C:/windows/     | File:/C:/windows\\     | File:/C:\windows        |
| File:/C:\windows\\      | File:/C:\windows/     | File://C:/windows      | File://C:/windows/      |
| File://C:/windows\\     | File://C:\windows     | File://C:\windows/     | File://C:\windows\\     |
| C:/windows              | C:/windows/           | C:/windows\\           | C:\windows              |
| C:\windows\\            | C:\windows/           | %WINDIR%               | %TMP%                   |
| %TEMP%                  | %SYSTEMDRIVE%         | %SYSTEMROOT%           | %APPDATA%               |
| %HOMEDRIVE%             | %HOMESHARE            |                        | <p><br></p>             |

## Scorciatoie

* Sticky Keys – Premi SHIFT 5 volte
* Mouse Keys – SHIFT+ALT+NUMLOCK
* High Contrast – SHIFT+ALT+PRINTSCN
* Toggle Keys – Tieni premuto NUMLOCK per 5 secondi
* Filter Keys – Tieni premuto il tasto destro SHIFT per 12 secondi
* WINDOWS+F1 – Ricerca di Windows
* WINDOWS+D – Mostra desktop
* WINDOWS+E – Avvia Esplora risorse di Windows
* WINDOWS+R – Esegui
* WINDOWS+U – Centro facilità di accesso
* WINDOWS+F – Cerca
* SHIFT+F10 – Menu contestuale
* CTRL+SHIFT+ESC – Task Manager
* CTRL+ALT+DEL – Schermata di avvio nelle versioni più recenti di Windows
* F1 – Guida F3 – Cerca
* F6 – Barra degli indirizzi
* F11 – Attiva/disattiva la modalità a schermo intero in Internet Explorer
* CTRL+H – Cronologia di Internet Explorer
* CTRL+T – Internet Explorer – Nuova scheda
* CTRL+N – Internet Explorer – Nuova pagina
* CTRL+O – Apri file
* CTRL+S – Salva CTRL+N – Nuovo RDP / Citrix
## Swipes

* Scorri dal lato sinistro verso destra per vedere tutte le finestre aperte, riducendo l'app KIOSK e accedendo direttamente a tutto il sistema operativo;
* Scorri dal lato destro verso sinistra per aprire il Centro di azione, riducendo l'app KIOSK e accedendo direttamente a tutto il sistema operativo;
* Scorri dall'alto verso il basso per rendere visibile la barra del titolo per un'app aperta in modalità schermo intero;
* Scorri verso l'alto dal basso per mostrare la barra delle applicazioni in un'app a schermo intero.

## Trucchi di Internet Explorer

### 'Barra degli strumenti per le immagini'

È una barra degli strumenti che appare in alto a sinistra dell'immagine quando viene cliccata. Sarai in grado di Salvare, Stampare, Inviare per posta, Aprire "Le mie immagini" in Esplora risorse. Il Kiosk deve utilizzare Internet Explorer.

### Protocollo Shell

Digita questi URL per ottenere una visualizzazione di Esplora risorse:

* `shell:Strumenti di amministrazione`
* `shell:Libreria documenti`
* `shell:Biblioteche`
* `shell:Profili utente`
* `shell:Personale`
* `shell:Cartella home di ricerca`
* `shell:Cartella posizioni di rete`
* `shell:Invia a`
* `shell:Profili utente`
* `shell:Strumenti di amministrazione comuni`
* `shell:Risorse del computer`
* `shell:Cartella Internet`
* `Shell:Profilo`
* `Shell:File di programma`
* `Shell:Sistema`
* `Shell:Pannello di controllo`
* `Shell:Windows`
* `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Pannello di controllo
* `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Il mio computer
* `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Risorse di rete
* `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

## Mostra le estensioni dei file

Consulta questa pagina per ulteriori informazioni: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# Trucchi dei browser

Backup delle versioni di iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

Crea una finestra di dialogo comune utilizzando JavaScript e accedi all'esplora risorse: `document.write('<input/type=file>')`
Fonte: https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## Gestures e pulsanti

* Scorri verso l'alto con quattro (o cinque) dita / Doppio tocco sul pulsante Home: Per visualizzare la vista multitasking e cambiare app

* Scorri in una direzione o nell'altra con quattro o cinque dita: Per passare all'app successiva/precedente

* Pizzica lo schermo con cinque dita / Tocca il pulsante Home / Scorri verso l'alto con 1 dito dal basso dello schermo in un movimento rapido verso l'alto: Per accedere alla schermata Home

* Scorri con un dito dal basso dello schermo per 1-2 pollici (lentamente): Comparirà il dock

* Scorri verso il basso dall'alto del display con 1 dito: Per visualizzare le notifiche

* Scorri verso il basso con 1 dito nell'angolo in alto a destra dello schermo: Per vedere il centro di controllo di iPad Pro

* Scorri con 1 dito dal lato sinistro dello schermo per 1-2 pollici: Per visualizzare la vista di Oggi

* Scorri rapidamente con 1 dito dal centro dello schermo verso destra o sinistra: Per passare all'app successiva/precedente

* Premi e tieni premuto il pulsante Accensione/Spegnimento in alto a destra dell'iPad + Sposta il cursore di spegnimento tutto a destra: Per spegnere

* Premi il pulsante Accensione/Spegnimento in alto a destra dell'iPad e il pulsante Home per alcuni secondi: Per forzare uno spegnimento forzato

* Premi il pulsante Accensione/Spegnimento in alto a destra dell'iPad e il pulsante Home rapidamente: Per fare uno screenshot che apparirà in basso a sinistra del display. Premi entrambi i pulsanti contemporaneamente molto brevemente, se li tieni premuti per alcuni secondi verrà eseguito uno spegnimento forzato.

## Scorciatoie

Dovresti avere una tastiera per iPad o un adattatore per tastiera USB. Qui verranno mostrate solo le scorciatoie che possono aiutare a uscire dall'applicazione.

| Tasto | Nome         |
| ----- | ------------ |
| ⌘     | Comando      |
| ⌥     | Opzione (Alt) |
| ⇧     | Maiusc       |
| ↩     | Invio        |
| ⇥     | Tab          |
| ^     | Control      |
| ←     | Freccia sinistra   |
| →     | Freccia destra  |
| ↑     | Freccia su     |
| ↓     | Freccia giù   |

### Scorciatoie di sistema

Queste scorciatoie sono per le impostazioni visive e le impostazioni audio, a seconda dell'uso dell'iPad.

| Scorciatoia | Azione                                                                         |
| ----------- | ------------------------------------------------------------------------------ |
| F1          | Abbassa luminosità schermo                                                     |
| F2          | Aumenta luminosità schermo                                                     |
| F7          | Brano precedente                                                               |
| F8          | Riproduci/metti in pausa                                                       |
| F9          | Brano successivo                                                               |
| F10         | Disattiva audio                                                                |
| F11         | Diminuisci volume                                                              |
| F12         | Aumenta volume                                                                 |
| ⌘ Spazio    | Visualizza un elenco di lingue disponibili; per sceglierne una, tocca di nuovo lo spazio. |

### Navigazione iPad

| Scorciatoia                                           | Azione                                                  |
| ----------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                    | Vai alla schermata Home                                 |
| ⌘⇧H (Comando-Maiusc-H)                                | Vai alla schermata Home                                 |
| ⌘ (Spazio)                                            | Apri Spotlight                                          |
| ⌘⇥ (Comando-Tab)                                      | Elenco delle ultime dieci app utilizzate                 |
| ⌘\~                                                   | Vai all'ultima app                                      |
| ⌘⇧3 (Comando-Maiusc-3)                                | Screenshot (passa il mouse in basso a sinistra per salvarlo o agire su di esso) |
| ⌘⇧4                                                   | Screenshot e aprilo nell'editor                        |
| Tieni premuto ⌘                                        | Elenco delle scorciatoie disponibili per l'app          |
| ⌘⌥D (Comando-Opzione/Alt-D)                           | Mostra il dock                                          |
| ^⌥H (Control-Opzione-H)                               | Pulsante Home                                           |
| ^⌥H H (Control-Opzione-H-H)                           | Mostra la barra di multitasking                         |
| ^⌥I (Control-Opzione-i)                               | Selettore di elementi                                   |
| Escape                                                | Pulsante Indietro                                       |
| → (Freccia destra)                                    | Elemento successivo                                     |
| ← (Freccia sinistra)                                  | Elemento precedente                                     |
| ↑↓ (Freccia su, Freccia giù)                          | Tocca contemporaneamente l'elemento selezionato          |
| ⌥ ↓ (Opzione-Freccia giù)                             | Scorri verso il basso                                   |
| ⌥↑ (Opzione-Freccia su)                               | Scorri verso l'alto                                    |
| ⌥← o ⌥→ (Opzione-Freccia sinistra o Opzione-Freccia destra) | Scorri verso sinistra o destra                          |
| ^⌥S (Control-Opzione-S)                               | Attiva o disattiva la lettura del testo VoiceOver        |
| ⌘⇧⇥ (Comando-Maiusc-Tab)                             | Passa all'app precedente                               |
| ⌘⇥ (Comando-Tab)                                      | Torna all'app originale                                |
| ←+→, quindi Opzione + ← o Opzione+→                    | Naviga attraverso il Dock                               |
### Scorciatoie di Safari

| Scorciatoia              | Azione                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Comando-L)          | Apri la posizione                                 |
| ⌘T                      | Apri una nuova scheda                             |
| ⌘W                      | Chiudi la scheda corrente                         |
| ⌘R                      | Aggiorna la scheda corrente                       |
| ⌘.                      | Interrompi il caricamento della scheda corrente    |
| ^⇥                      | Passa alla scheda successiva                      |
| ^⇧⇥ (Control-Shift-Tab) | Passa alla scheda precedente                      |
| ⌘L                      | Seleziona l'input di testo/campo URL per modificarlo |
| ⌘⇧T (Comando-Shift-T)   | Apri l'ultima scheda chiusa (può essere utilizzato più volte) |
| ⌘\[                     | Torna indietro di una pagina nella cronologia di navigazione |
| ⌘]                      | Vai avanti di una pagina nella cronologia di navigazione |
| ⌘⇧R                     | Attiva la modalità Lettore                        |

### Scorciatoie di Mail

| Scorciatoia                   | Azione                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Apri la posizione                |
| ⌘T                         | Apri una nuova scheda               |
| ⌘W                         | Chiudi la scheda corrente        |
| ⌘R                         | Aggiorna la scheda corrente      |
| ⌘.                         | Interrompi il caricamento della scheda corrente |
| ⌘⌥F (Comando-Opzione/Alt-F) | Cerca nella tua casella di posta       |

# Riferimenti

* [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
* [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
* [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
* [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)


<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
