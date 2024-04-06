<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


# Verificar BSSIDs

Quando você recebe uma captura cujo tráfego principal é Wifi usando o WireShark, você pode começar a investigar todos os SSIDs da captura com _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Força Bruta

Uma das colunas dessa tela indica se **alguma autenticação foi encontrada dentro do pcap**. Se for o caso, você pode tentar força bruta usando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
Por exemplo, ele irá recuperar a frase de segurança WPA protegendo uma PSK (chave pré-compartilhada), que será necessária para descriptografar o tráfego posteriormente.

# Dados em Beacons / Canal Lateral

Se você suspeitar que **dados estão vazando dentro dos beacons de uma rede Wifi**, você pode verificar os beacons da rede usando um filtro como o seguinte: `wlan contains <NOMEdaREDE>`, ou `wlan.ssid == "NOMEdaREDE"` procurar nos pacotes filtrados por strings suspeitas.

# Encontrar Endereços MAC Desconhecidos em uma Rede Wifi

O seguinte link será útil para encontrar as **máquinas enviando dados dentro de uma Rede Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se você já conhece os **endereços MAC, você pode removê-los da saída** adicionando verificações como esta: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Uma vez que você tenha detectado **endereços MAC** desconhecidos comunicando dentro da rede, você pode usar **filtros** como o seguinte: `wlan.addr==<endereço MAC> && (ftp || http || ssh || telnet)` para filtrar seu tráfego. Note que os filtros ftp/http/ssh/telnet são úteis se você tiver descriptografado o tráfego.

# Descriptografar Tráfego

Editar --> Preferências --> Protocolos --> IEEE 802.11--> Editar

![](<../../../.gitbook/assets/image (426).png>)





<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Obtenha o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
