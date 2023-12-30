# Truques do Wireshark

## Truques do Wireshark

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Melhore suas habilidades no Wireshark

### Tutoriais

Os seguintes tutoriais são incríveis para aprender alguns truques básicos interessantes:

* [https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/](https://unit42.paloaltonetworks.com/unit42-customizing-wireshark-changing-column-display/)
* [https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)
* [https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/](https://unit42.paloaltonetworks.com/using-wireshark-identifying-hosts-and-users/)
* [https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/](https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/)

### Informações Analisadas

**Informações de Especialistas**

Clicando em _**Analyze** --> **Expert Information**_ você terá uma **visão geral** do que está acontecendo nos pacotes **analisados**:

![](<../../../.gitbook/assets/image (570).png>)

**Endereços Resolvidos**

Em _**Statistics --> Resolved Addresses**_ você pode encontrar várias **informações** que foram "**resolvidas**" pelo Wireshark, como porta/transporte para protocolo, MAC para o fabricante, etc. É interessante saber o que está implicado na comunicação.

![](<../../../.gitbook/assets/image (571).png>)

**Hierarquia de Protocolos**

Em _**Statistics --> Protocol Hierarchy**_ você pode encontrar os **protocolos** **envolvidos** na comunicação e dados sobre eles.

![](<../../../.gitbook/assets/image (572).png>)

**Conversas**

Em _**Statistics --> Conversations**_ você pode encontrar um **resumo das conversas** na comunicação e dados sobre elas.

![](<../../../.gitbook/assets/image (573).png>)

**Pontos Finais**

Em _**Statistics --> Endpoints**_ você pode encontrar um **resumo dos pontos finais** na comunicação e dados sobre cada um deles.

![](<../../../.gitbook/assets/image (575).png>)

**Informações DNS**

Em _**Statistics --> DNS**_ você pode encontrar estatísticas sobre as solicitações DNS capturadas.

![](<../../../.gitbook/assets/image (577).png>)

**Gráfico I/O**

Em _**Statistics --> I/O Graph**_ você pode encontrar um **gráfico da comunicação.**

![](<../../../.gitbook/assets/image (574).png>)

### Filtros

Aqui você pode encontrar filtros do Wireshark dependendo do protocolo: [https://www.wireshark.org/docs/dfref/](https://www.wireshark.org/docs/dfref/)\
Outros filtros interessantes:

* `(http.request or ssl.handshake.type == 1) and !(udp.port eq 1900)`
* Tráfego HTTP e HTTPS inicial
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002) and !(udp.port eq 1900)`
* Tráfego HTTP e HTTPS inicial + TCP SYN
* `(http.request or ssl.handshake.type == 1 or tcp.flags eq 0x0002 or dns) and !(udp.port eq 1900)`
* Tráfego HTTP e HTTPS inicial + TCP SYN + solicitações DNS

### Pesquisa

Se você quer **pesquisar** por **conteúdo** dentro dos **pacotes** das sessões, pressione _CTRL+f_. Você pode adicionar novas camadas à barra de informações principais (No., Time, Source, etc.) clicando com o botão direito e depois em editar coluna.

Prática: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net)

## Identificando Domínios

Você pode adicionar uma coluna que mostra o cabeçalho Host HTTP:

![](<../../../.gitbook/assets/image (403).png>)

E uma coluna que adiciona o nome do servidor de uma conexão HTTPS iniciante (**ssl.handshake.type == 1**):

![](<../../../.gitbook/assets/image (408) (1).png>)

## Identificando nomes de host locais

### Do DHCP

No Wireshark atual, em vez de `bootp`, você precisa procurar por `DHCP`

![](<../../../.gitbook/assets/image (404).png>)

### Do NBNS

![](<../../../.gitbook/assets/image (405).png>)

## Descriptografando TLS

### Descriptografando tráfego https com chave privada do servidor

_edit>preference>protocol>ssl>_

![](<../../../.gitbook/assets/image (98).png>)

Pressione _Edit_ e adicione todos os dados do servidor e a chave privada (_IP, Port, Protocol, Key file e password_)

### Descriptografando tráfego https com chaves de sessão simétricas

Acontece que o Firefox e o Chrome ambos suportam o registro da chave de sessão simétrica usada para criptografar o tráfego TLS em um arquivo. Você pode então apontar o Wireshark para esse arquivo e pronto! tráfego TLS descriptografado. Mais em: [https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/](https://redflagsecurity.net/2019/03/10/decrypting-tls-wireshark/)\
Para detectar isso, procure no ambiente pela variável `SSLKEYLOGFILE`

Um arquivo de chaves compartilhadas terá esta aparência:

![](<../../../.gitbook/assets/image (99).png>)

Para importar isso no Wireshark, vá para _edit > preference > protocol > ssl > e importe-o em (Pre)-Master-Secret log filename:

![](<../../../.gitbook/assets/image (100).png>)

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
<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
