<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Verificar BSSIDs

Quando você recebe uma captura cujo tráfego principal é Wifi usando o WireShark, você pode começar a investigar todos os SSIDs da captura com _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Força Bruta

Uma das colunas dessa tela indica se **alguma autenticação foi encontrada dentro do pcap**. Se esse for o caso, você pode tentar forçar a entrada usando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Por exemplo, ele recuperará a frase-senha WPA protegendo um PSK (pre shared-key), que será necessária para descriptografar o tráfego mais tarde.

# Dados em Beacons / Canal Lateral

Se você suspeita que **dados estão sendo vazados dentro de beacons de uma rede Wifi**, você pode verificar os beacons da rede usando um filtro como o seguinte: `wlan contains <NAMEofNETWORK>`, ou `wlan.ssid == "NAMEofNETWORK"` procure dentro dos pacotes filtrados por strings suspeitas.

# Encontrar Endereços MAC Desconhecidos em Uma Rede Wifi

O seguinte link será útil para encontrar as **máquinas enviando dados dentro de uma Rede Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se você já conhece **endereços MAC, você pode removê-los da saída** adicionando verificações como esta: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Uma vez que você tenha detectado endereços **MAC desconhecidos** comunicando dentro da rede, você pode usar **filtros** como o seguinte: `wlan.addr==<MAC address> && (ftp || http || ssh || telnet)` para filtrar o tráfego dele. Note que filtros ftp/http/ssh/telnet são úteis se você descriptografou o tráfego.

# Descriptografar Tráfego

Editar --> Preferências --> Protocolos --> IEEE 802.11--> Editar

![](<../../../.gitbook/assets/image (426).png>)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
