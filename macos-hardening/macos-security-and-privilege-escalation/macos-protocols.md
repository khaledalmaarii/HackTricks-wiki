# Servizi e protocolli di rete macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Servizi di accesso remoto

Questi sono i servizi comuni di macOS per accedervi in remoto.\
È possibile abilitare/disabilitare questi servizi in `Impostazioni di sistema` --> `Condivisione`

* **VNC**, conosciuto come "Condivisione schermo" (tcp:5900)
* **SSH**, chiamato "Accesso remoto" (tcp:22)
* **Apple Remote Desktop** (ARD), o "Gestione remota" (tcp:3283, tcp:5900)
* **AppleEvent**, conosciuto come "Evento Apple remoto" (tcp:3031)

Verifica se uno di questi è abilitato eseguendo:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) è una versione migliorata di [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) adattata per macOS, che offre funzionalità aggiuntive. Una vulnerabilità significativa in ARD è il suo metodo di autenticazione per la password dello schermo di controllo, che utilizza solo i primi 8 caratteri della password, rendendola suscettibile ad attacchi di [brute force](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) con strumenti come Hydra o [GoRedShell](https://github.com/ahhh/GoRedShell/), poiché non ci sono limiti di velocità predefiniti.

Le istanze vulnerabili possono essere identificate utilizzando lo script `vnc-info` di **nmap**. I servizi che supportano `VNC Authentication (2)` sono particolarmente suscettibili ad attacchi di brute force a causa della troncatura della password a 8 caratteri.

Per abilitare ARD per varie attività amministrative come l'escalation dei privilegi, l'accesso GUI o il monitoraggio dell'utente, utilizzare il seguente comando:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD fornisce livelli di controllo versatili, tra cui osservazione, controllo condiviso e controllo completo, con sessioni che persistono anche dopo la modifica della password dell'utente. Consente di inviare comandi Unix direttamente ed eseguirli come root per gli utenti amministrativi. La pianificazione delle attività e la ricerca remota di Spotlight sono funzionalità notevoli che facilitano la ricerca remota a basso impatto di file sensibili su più macchine.


## Protocollo Bonjour

Bonjour, una tecnologia progettata da Apple, consente ai dispositivi sulla stessa rete di rilevare i servizi offerti l'uno dall'altro. Conosciuto anche come Rendezvous, Zero Configuration o Zeroconf, consente a un dispositivo di unirsi a una rete TCP/IP, scegliere automaticamente un indirizzo IP e diffondere i suoi servizi agli altri dispositivi di rete.

La rete Zero Configuration, fornita da Bonjour, garantisce che i dispositivi possano:
* Ottenere automaticamente un indirizzo IP anche in assenza di un server DHCP.
* Eseguire la traduzione del nome in indirizzo senza richiedere un server DNS.
* Scoprire i servizi disponibili sulla rete.

I dispositivi che utilizzano Bonjour si assegnano automaticamente un indirizzo IP dall'intervallo 169.254/16 e ne verificano l'unicità sulla rete. I Mac mantengono una voce nella tabella di routing per questa subnet, verificabile tramite `netstat -rn | grep 169`.

Per il DNS, Bonjour utilizza il protocollo **Multicast DNS (mDNS)**. mDNS opera sulla porta **5353/UDP**, utilizzando **query DNS standard** ma indirizzate all'indirizzo multicast 224.0.0.251. Questo approccio garantisce che tutti i dispositivi in ascolto sulla rete possano ricevere e rispondere alle query, facilitando l'aggiornamento dei loro record.

Al momento dell'ingresso nella rete, ogni dispositivo seleziona autonomamente un nome, di solito terminante con **.local**, che può essere derivato dal nome host o generato casualmente.

La scoperta dei servizi all'interno della rete è facilitata da **DNS Service Discovery (DNS-SD)**. Sfruttando il formato dei record SRV DNS, DNS-SD utilizza i record PTR DNS per consentire l'elenco di più servizi. Un client che cerca un servizio specifico richiederà un record PTR per `<Servizio>.<Dominio>`, ricevendo in cambio un elenco di record PTR formattati come `<Istanza>.<Servizio>.<Dominio>` se il servizio è disponibile da più host.


L'utilità `dns-sd` può essere utilizzata per **scoprire e pubblicizzare i servizi di rete**. Ecco alcuni esempi di utilizzo:

### Ricerca di servizi SSH

Per cercare i servizi SSH sulla rete, viene utilizzato il seguente comando:
```bash
dns-sd -B _ssh._tcp
```
Questo comando avvia la ricerca dei servizi _ssh._tcp e mostra dettagli come timestamp, flag, interfaccia, dominio, tipo di servizio e nome dell'istanza.

### Pubblicizzare un servizio HTTP

Per pubblicizzare un servizio HTTP, è possibile utilizzare:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Questo comando registra un servizio HTTP chiamato "Index" sulla porta 80 con un percorso di `/index.html`.

Per cercare i servizi HTTP sulla rete:
```bash
dns-sd -B _http._tcp
```
Quando un servizio viene avviato, annuncia la sua disponibilità a tutti i dispositivi sulla sottorete tramite multicast. I dispositivi interessati a questi servizi non devono inviare richieste, ma semplicemente ascoltare queste segnalazioni.

Per un'interfaccia più user-friendly, l'app **Discovery - DNS-SD Browser**, disponibile sull'Apple App Store, può visualizzare i servizi offerti nella tua rete locale.

In alternativa, è possibile scrivere script personalizzati per esplorare e scoprire servizi utilizzando la libreria `python-zeroconf`. Lo script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) dimostra come creare un browser di servizi per i servizi `_http._tcp.local.`, stampando i servizi aggiunti o rimossi:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Disabilitazione di Bonjour
Se ci sono preoccupazioni per la sicurezza o altre ragioni per disabilitare Bonjour, è possibile disattivarlo utilizzando il seguente comando:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Riferimenti

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
