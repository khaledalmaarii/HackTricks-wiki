{% hint style="success" %}
Aprenda e pratique AWS Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Treinamento HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Treinamento HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Apoie o HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

# Verificar BSSIDs

Quando você recebe uma captura cujo tráfego principal é Wifi usando o WireShark, você pode começar a investigar todos os SSIDs da captura com _Wireless --> WLAN Traffic_:

![](<../../../.gitbook/assets/image (424).png>)

![](<../../../.gitbook/assets/image (425).png>)

## Força Bruta

Uma das colunas dessa tela indica se **alguma autenticação foi encontrada dentro do pcap**. Se for o caso, você pode tentar força bruta usando `aircrack-ng`:
```bash
aircrack-ng -w pwds-file.txt -b <BSSID> file.pcap
```
# Dados nos Beacons / Canal Lateral

Se suspeitar que **dados estão sendo vazados dentro dos beacons de uma rede Wifi**, você pode verificar os beacons da rede usando um filtro como o seguinte: `wlan contains <NOMEdaREDE>`, ou `wlan.ssid == "NOMEdaREDE"` e procurar dentro dos pacotes filtrados por strings suspeitas.

# Encontrar Endereços MAC Desconhecidos em uma Rede Wifi

O seguinte link será útil para encontrar as **máquinas enviando dados dentro de uma Rede Wifi**:

* `((wlan.ta == e8:de:27:16:70:c9) && !(wlan.fc == 0x8000)) && !(wlan.fc.type_subtype == 0x0005) && !(wlan.fc.type_subtype ==0x0004) && !(wlan.addr==ff:ff:ff:ff:ff:ff) && wlan.fc.type==2`

Se você já conhece os **endereços MAC, pode removê-los da saída** adicionando verificações como esta: `&& !(wlan.addr==5c:51:88:31:a0:3b)`

Uma vez que você tenha detectado **endereços MAC desconhecidos** comunicando-se dentro da rede, você pode usar **filtros** como o seguinte: `wlan.addr==<endereço MAC> && (ftp || http || ssh || telnet)` para filtrar seu tráfego. Note que os filtros ftp/http/ssh/telnet são úteis se você tiver descriptografado o tráfego.

# Descriptografar Tráfego

Editar --> Preferências --> Protocolos --> IEEE 802.11 --> Editar

![](<../../../.gitbook/assets/image (426).png>)
