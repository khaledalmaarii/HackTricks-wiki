# Dicas do Wireshark

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

- Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
- Obtenha o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
- **Compartilhe suas dicas de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares de roubo**.

O principal objetivo do WhiteIntel é combater a apropriação de contas e ataques de ransomware resultantes de malwares de roubo de informações.

Você pode verificar o site deles e experimentar o mecanismo gratuitamente em:

{% embed url="https://whiteintel.io" %}

***

## Melhore suas habilidades no Wireshark

### Tutoriais

Os seguintes tutoriais são incríveis para aprender alguns truques básicos legais:

- [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
- [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
- [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
- [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informações Analisadas

**Informação de Especialista**

Clicando em _**Analyze** --> **Expert Information**_ você terá uma **visão geral** do que está acontecendo nos pacotes **analisados**:

![](<../../../.gitbook/assets/image (256).png>)

**Endereços Resolvidos**

Em _**Statistics --> Resolved Addresses**_ você pode encontrar várias **informações** que foram "**resolvidas**" pelo wireshark, como porta/transporte para protocolo, MAC para o fabricante, etc. É interessante saber o que está implicado na comunicação.

![](<../../../.gitbook/assets/image (893).png>)

**Hierarquia de Protocolo**

Em _**Statistics --> Protocol Hierarchy**_ você pode encontrar os **protocolos** **envolvidos** na comunicação e dados sobre eles.

![](<../../../.gitbook/assets/image (586).png>)

**Conversas**

Em _**Statistics --> Conversations**_ você pode encontrar um **resumo das conversas** na comunicação e dados sobre elas.

![](<../../../.gitbook/assets/image (453).png>)

**Pontos Finais**

Em _**Statistics --> Endpoints**_ você pode encontrar um **resumo dos pontos finais** na comunicação e dados sobre cada um deles.

![](<../../../.gitbook/assets/image (896).png>)

**Informações de DNS**

Em _**Statistics --> DNS**_ você pode encontrar estatísticas sobre a solicitação de DNS capturada.

![](<../../../.gitbook/assets/image (1063).png>)

**Gráfico de E/S**

Em _**Statistics --> I/O Graph**_ você pode encontrar um **gráfico da comunicação**.

![](<../../../.gitbook/assets/image (992).png>)

### Filtros

Aqui você pode encontrar filtro do wireshark dependendo do protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Outros filtros interessantes:

- `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
- Tráfego HTTP e HTTPS inicial
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
- Tráfego HTTP e HTTPS inicial + SYN TCP
- `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
- Tráfego HTTP e HTTPS inicial + SYN TCP + solicitações DNS

### Pesquisa

Se você deseja **pesquisar** por **conteúdo** dentro dos **pacotes** das sessões, pressione _CTRL+f_. Você pode adicionar novas camadas à barra de informações principal (No., Time, Source, etc.) pressionando o botão direito e depois editar a coluna.

### Laboratórios pcap gratuitos

**Pratique com os desafios gratuitos em:** [**https://www.malware-traffic-analysis.net/**](https://www.malware-traffic-analysis.net)

## Identificando Domínios

Você pode adicionar uma coluna que mostra o cabeçalho Host HTTP:

![](<../../../.gitbook/assets/image (639).png>)

E uma coluna que adiciona o nome do servidor de uma conexão HTTPS iniciante (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identificando nomes de host locais

### Do DHCP

No Wireshark atual, em vez de `bootp`, você precisa procurar por `DHCP`

![](<../../../.gitbook/assets/image (1013).png>)

### Do NBNS

![](<../../../.gitbook/assets/image (1003).png>)

## Descriptografando TLS

### Descriptografando tráfego https com chave privada do servidor

_editar>preferência>protocolo>ssl>_

![](<../../../.gitbook/assets/image (1103).png>)

Pressione _Editar_ e adicione todos os dados do servidor e da chave privada (_IP, Porta, Protocolo, Arquivo de chave e senha_)

### Descriptografando tráfego https com chaves de sessão simétricas

Tanto o Firefox quanto o Chrome têm a capacidade de registrar chaves de sessão TLS, que podem ser usadas com o Wireshark para descriptografar o tráfego TLS. Isso permite uma análise aprofundada das comunicações seguras. Mais detalhes sobre como realizar essa descriptografia podem ser encontrados em um guia em [Red Flag Security](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/).

Para detectar isso, pesquise no ambiente pela variável `SSLKEYLOGFILE`

Um arquivo de chaves compartilhadas se parecerá com isso:

![](<../../../.gitbook/assets/image (820).png>)

Para importar isso no wireshark, vá para \_editar > preferência > protocolo > ssl > e importe em (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (989).png>)
## Comunicação ADB

Extrair um APK de uma comunicação ADB onde o APK foi enviado:
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
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares stealers**.

O principal objetivo do WhiteIntel é combater a apropriação de contas e ataques de ransomware resultantes de malwares que roubam informações.

Você pode acessar o site deles e experimentar o mecanismo gratuitamente em:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
