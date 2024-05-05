# Analisi Pcap Wifi

<details>

<summary><strong>Impara l'hacking AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Controlla i BSSID

Quando ricevi una cattura il cui traffico principale è Wifi utilizzando WireShark, puoi iniziare a investigare tutti gli SSID della cattura con _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (106).png>)

![](<../../../.gitbook/assets/image (492).png>)

### Forza Bruta

Una delle colonne di quella schermata indica se **è stata trovata qualche autenticazione all'interno del pcap**. In tal caso, puoi provare a forzare la password utilizzando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
## Dati nei Beacons / Canale Laterale

Se sospetti che **i dati stiano trapelando nei beacon di una rete Wifi**, puoi controllare i beacon della rete utilizzando un filtro come il seguente: `wlan contains <NOMEdellaRETE>`, o `wlan.ssid == "NOMEdellaRETE"` cerca nei pacchetti filtrati stringhe sospette.

## Trovare Indirizzi MAC Sconosciuti in una Rete Wifi

Il seguente link sarà utile per trovare le **macchine che inviano dati all'interno di una Rete Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se conosci già gli **indirizzi MAC puoi rimuoverli dall'output** aggiungendo controlli come questo: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Una volta individuati gli **indirizzi MAC sconosciuti** che comunicano all'interno della rete, puoi utilizzare **filtri** come il seguente: `wlan.addr==<indirizzo MAC> && (ftp || http || ssh || telnet)` per filtrare il traffico. Nota che i filtri ftp/http/ssh/telnet sono utili se hai decifrato il traffico.

## Decifrare il Traffico

Modifica --> Preferenze --> Protocolli --> IEEE 802.11--> Modifica

![](<../../../.gitbook/assets/image (499).png>)

<details>

<summary><strong>Impara l'hacking di AWS da zero a eroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
