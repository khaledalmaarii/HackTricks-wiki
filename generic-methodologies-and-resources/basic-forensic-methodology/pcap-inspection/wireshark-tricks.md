# Truques do Wireshark

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-nos no** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}


## Melhore suas habilidades no Wireshark

### Tutoriais

Os seguintes tutoriais são incríveis para aprender alguns truques básicos legais:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informações Analisadas

**Informações do Especialista**

Clicando em _**Analisar** --> **Informações do Especialista**_ você terá uma **visão geral** do que está acontecendo nos pacotes **analisados**:

![](<../../../.gitbook/assets/image (256).png>)

**Endereços Resolvidos**

Em _**Estatísticas --> Endereços Resolvidos**_ você pode encontrar várias **informações** que foram "**resolvidas**" pelo wireshark, como porta/transporte para protocolo, MAC para o fabricante, etc. É interessante saber o que está implicado na comunicação.

![](<../../../.gitbook/assets/image (893).png>)

**Hierarquia de Protocolos**

Em _**Estatísticas --> Hierarquia de Protocolos**_ você pode encontrar os **protocolos** **envolvidos** na comunicação e dados sobre eles.

![](<../../../.gitbook/assets/image (586).png>)

**Conversas**

Em _**Estatísticas --> Conversas**_ você pode encontrar um **resumo das conversas** na comunicação e dados sobre elas.

![](<../../../.gitbook/assets/image (453).png>)

**Pontos Finais**

Em _**Estatísticas --> Pontos Finais**_ você pode encontrar um **resumo dos pontos finais** na comunicação e dados sobre cada um deles.

![](<../../../.gitbook/assets/image (896).png>)

**Informações DNS**

Em _**Estatísticas --> DNS**_ você pode encontrar estatísticas sobre a solicitação DNS capturada.

![](<../../../.gitbook/assets/image (1063).png>)

**Gráfico I/O**

Em _**Estatísticas --> Gráfico I/O**_ você pode encontrar um **gráfico da comunicação.**

![](<../../../.gitbook/assets/image (992).png>)

### Filtros

Aqui você pode encontrar filtros do wireshark dependendo do protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Outros filtros interessantes:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* Tráfego HTTP e HTTPS inicial
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* Tráfego HTTP e HTTPS inicial + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* Tráfego HTTP e HTTPS inicial + TCP SYN + solicitações DNS

### Pesquisa

Se você quiser **pesquisar** por **conteúdo** dentro dos **pacotes** das sessões, pressione _CTRL+f_. Você pode adicionar novas camadas à barra de informações principal (No., Hora, Fonte, etc.) pressionando o botão direito e depois editando a coluna.

### Laboratórios pcap gratuitos

**Pratique com os desafios gratuitos de:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificando Domínios

Você pode adicionar uma coluna que mostra o cabeçalho Host HTTP:

![](<../../../.gitbook/assets/image (639).png>)

E uma coluna que adiciona o nome do Servidor de uma conexão HTTPS iniciada (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identificando nomes de host locais

### Do DHCP

No Wireshark atual, em vez de `bootp`, você precisa procurar por `DHCP`

![](<../../../.gitbook/assets/image (1013).png>)

### Do NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## Decriptando TLS

### Decriptando tráfego https com a chave privada do servidor

_edit>preferência>protocolo>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

Pressione _Editar_ e adicione todos os dados do servidor e a chave privada (_IP, Porta, Protocolo, Arquivo de chave e senha_)

### Decriptando tráfego https com chaves de sessão simétricas

Tanto o Firefox quanto o Chrome têm a capacidade de registrar chaves de sessão TLS, que podem ser usadas com o Wireshark para decriptar tráfego TLS. Isso permite uma análise aprofundada das comunicações seguras. Mais detalhes sobre como realizar essa decriptação podem ser encontrados em um guia na [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Para detectar isso, procure dentro do ambiente pela variável `SSLKEYLOGFILE`

Um arquivo de chaves compartilhadas terá a seguinte aparência:

![](<../../../.gitbook/assets/image (820).png>)

Para importar isso no wireshark, vá para \_editar > preferência > protocolo > ssl > e importe-o no nome do arquivo de log (Pre)-Master-Secret:

![](<../../../.gitbook/assets/image (989).png>)

## Comunicação ADB

Extraia um APK de uma comunicação ADB onde o APK foi enviado:
```python
from scapy.all import *

pcap = rdpcap("final2.pcapng")

def rm_data(data):
splitted = data.split(b"DATA")
if len(splitted) == 1:
return data
else:
return splitted[0]+splitted[1][4:]

all_bytes = b""
for pkt in pcap:
if Raw in pkt:
a = pkt[Raw]
if b"WRTE" == bytes(a)[:4]:
all_bytes += rm_data(bytes(a)[24:])
else:
all_bytes += rm_data(bytes(a))
print(all_bytes)

f = open('all_bytes.data', 'w+b')
f.write(all_bytes)
f.close()
```
{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
