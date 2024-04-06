<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo Telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>


# Verifica BSSID

Quando ricevi una cattura il cui traffico principale è Wifi utilizzando WireShark, puoi iniziare a investigare tutti gli SSID della cattura con _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Brute Force

Una delle colonne di quella schermata indica se **è stata trovata un'autenticazione all'interno del pcap**. In tal caso, puoi provare a forzarla utilizzando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Ad esempio, recupererà la passphrase WPA che protegge una PSK (pre shared-key), che sarà necessaria per decrittare il traffico in seguito.

# Dati nei Beacon / Canale Laterale

Se sospetti che **i dati vengano rivelati all'interno dei beacon di una rete Wifi**, puoi controllare i beacon della rete utilizzando un filtro come il seguente: `wlan contiene <NOMEdellaRETE>`, o `wlan.ssid == "NOMEdellaRETE"` cerca all'interno dei pacchetti filtrati le stringhe sospette.

# Trova Indirizzi MAC Sconosciuti in una Rete Wifi

Il seguente link sarà utile per trovare le **macchine che inviano dati all'interno di una rete Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se conosci già gli **indirizzi MAC, puoi rimuoverli dall'output** aggiungendo controlli come questo: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Una volta individuati gli **indirizzi MAC sconosciuti** che comunicano all'interno della rete, puoi utilizzare **filtri** come il seguente: `wlan.addr==<indirizzo MAC> && (ftp || http || ssh || telnet)` per filtrare il traffico. Nota che i filtri ftp/http/ssh/telnet sono utili se hai decrittato il traffico.

# Decrittare il Traffico

Modifica --> Preferenze --> Protocolli --> IEEE 802.11 --> Modifica

![](<../../../.gitbook/assets/image (426).png>)





<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PACCHETTI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
