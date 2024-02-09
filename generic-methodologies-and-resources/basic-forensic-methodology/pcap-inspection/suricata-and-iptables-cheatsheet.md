# Cheatsheet do Suricata & Iptables

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Iptables

### Cadeias

No iptables, listas de regras conhecidas como cadeias são processadas sequencialmente. Entre essas, três cadeias principais estão universalmente presentes, com outras como NAT sendo potencialmente suportadas, dependendo das capacidades do sistema.

- **Cadeia de Entrada**: Utilizada para gerenciar o comportamento das conexões de entrada.
- **Cadeia de Encaminhamento**: Empregada para lidar com conexões de entrada que não são destinadas ao sistema local. Isso é típico para dispositivos que atuam como roteadores, onde os dados recebidos são destinados a ser encaminhados para outro destino. Esta cadeia é relevante principalmente quando o sistema está envolvido em roteamento, NATing ou atividades similares.
- **Cadeia de Saída**: Dedicada à regulamentação das conexões de saída.

Essas cadeias garantem o processamento ordenado do tráfego de rede, permitindo a especificação de regras detalhadas que regem o fluxo de dados para dentro, através e para fora de um sistema.
```bash
# Delete all rules
iptables -F

# List all rules
iptables -L
iptables -S

# Block IP addresses & ports
iptables -I INPUT -s ip1,ip2,ip3 -j DROP
iptables -I INPUT -p tcp --dport 443 -j DROP
iptables -I INPUT -s ip1,ip2 -p tcp --dport 443 -j DROP

# String based drop
## Strings are case sensitive (pretty easy to bypass if you want to check an SQLi for example)
iptables -I INPUT -p tcp --dport <port_listening> -m string --algo bm --string '<payload>' -j DROP
iptables -I OUTPUT -p tcp --sport <port_listening> -m string --algo bm --string 'CTF{' -j DROP
## You can also check for the hex, base64 and double base64 of the expected CTF flag chars

# Drop every input port except some
iptables -P INPUT DROP # Default to drop
iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT


# Persist Iptables
## Debian/Ubuntu:
apt-get install iptables-persistent
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
iptables-restore < /etc/iptables/rules.v4
##RHEL/CentOS:
iptables-save > /etc/sysconfig/iptables
ip6tables-save > /etc/sysconfig/ip6tables
iptables-restore < /etc/sysconfig/iptables
```
## Suricata

### Instalação e Configuração
```bash
# Install details from: https://suricata.readthedocs.io/en/suricata-6.0.0/install.html#install-binary-packages
# Ubuntu
add-apt-repository ppa:oisf/suricata-stable
apt-get update
apt-get install suricata

# Debian
echo "deb http://http.debian.net/debian buster-backports main" > \
/etc/apt/sources.list.d/backports.list
apt-get update
apt-get install suricata -t buster-backports

# CentOS
yum install epel-release
yum install suricata

# Get rules
suricata-update
suricata-update list-sources #List sources of the rules
suricata-update enable-source et/open #Add et/open rulesets
suricata-update
## To use the dowloaded rules update the following line in /etc/suricata/suricata.yaml
default-rule-path: /var/lib/suricata/rules
rule-files:
- suricata.rules

# Run
## Add rules in /etc/suricata/rules/suricata.rules
systemctl suricata start
suricata -c /etc/suricata/suricata.yaml -i eth0


# Reload rules
suricatasc -c ruleset-reload-nonblocking
## or set the follogin in /etc/suricata/suricata.yaml
detect-engine:
- rule-reload: true

# Validate suricata config
suricata -T -c /etc/suricata/suricata.yaml -v

# Configure suricata as IPs
## Config drop to generate alerts
## Search for the following lines in /etc/suricata/suricata.yaml and remove comments:
- drop:
alerts: yes
flows: all

## Forward all packages to the queue where suricata can act as IPS
iptables -I INPUT -j NFQUEUE
iptables -I OUTPUT -j NFQUEUE

## Start suricata in IPS mode
suricata -c /etc/suricata/suricata.yaml  -q 0
### or modify the service config file as:
systemctl edit suricata.service

[Service]
ExecStart=
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid -q 0 -vvv
Type=simple

systemctl daemon-reload
```
### Definições de Regras

[Da documentação:](https://github.com/OISF/suricata/blob/master/doc/userguide/rules/intro.rst) Uma regra/assinatura consiste no seguinte:

* A **ação**, determina o que acontece quando a assinatura corresponde.
* O **cabeçalho**, define o protocolo, endereços IP, portas e direção da regra.
* As **opções da regra**, definem os detalhes da regra.
```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
#### **Ações válidas são**

* alerta - gerar um alerta
* passar - parar a inspeção adicional do pacote
* **drop** - descartar o pacote e gerar um alerta
* **rejeitar** - enviar um erro RST/ICMP inacessível para o remetente do pacote correspondente.
* rejeitarsrc - o mesmo que apenas _rejeitar_
* rejeitardest - enviar um pacote de erro RST/ICMP para o destinatário do pacote correspondente.
* rejeitarambos - enviar pacotes de erro RST/ICMP para ambos os lados da conversa.

#### **Protocolos**

* tcp (para tráfego tcp)
* udp
* icmp
* ip (ip significa 'todos' ou 'qualquer')
* _protocolos de camada 7_: http, ftp, tls, smb, dns, ssh... (mais na [**documentação**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/intro.html))

#### Endereços de Origem e Destino

Suporta intervalos de IP, negações e uma lista de endereços:

| Exemplo                        | Significado                             |
| ------------------------------ | ---------------------------------------- |
| ! 1.1.1.1                      | Todos os endereços IP exceto 1.1.1.1     |
| !\[1.1.1.1, 1.1.1.2]           | Todos os endereços IP exceto 1.1.1.1 e 1.1.1.2 |
| $HOME\_NET                     | Sua definição de HOME\_NET no yaml      |
| \[$EXTERNAL\_NET, !$HOME\_NET] | EXTERNAL\_NET e não HOME\_NET           |
| \[10.0.0.0/24, !10.0.0.5]      | 10.0.0.0/24 exceto 10.0.0.5            |

#### Portas de Origem e Destino

Suporta intervalos de portas, negações e listas de portas

| Exemplo         | Significado                            |
| --------------- | -------------------------------------- |
| qualquer         | qualquer endereço                       |
| \[80, 81, 82]   | porta 80, 81 e 82                      |
| \[80: 82]       | Intervalo de 80 a 82                   |
| \[1024: ]       | De 1024 até o número de porta mais alto |
| !80             | Todas as portas exceto 80              |
| \[80:100,!99]   | Intervalo de 80 a 100, exceto 99       |
| \[1:80,!\[2,4]] | Intervalo de 1 a 80, exceto portas 2 e 4 |

#### Direção

É possível indicar a direção da regra de comunicação sendo aplicada:
```
source -> destination
source <> destination  (both directions)
```
#### Palavras-chave

Existem **centenas de opções** disponíveis no Suricata para buscar o **pacote específico** que você está procurando, aqui será mencionado se algo interessante for encontrado. Consulte a [**documentação**](https://suricata.readthedocs.io/en/suricata-6.0.0/rules/index.html) para mais informações!
```bash
# Meta Keywords
msg: "description"; #Set a description to the rule
sid:123 #Set a unique ID to the rule
rev:1 #Rule revision number
config classification: not-suspicious,Not Suspicious Traffic,3 #Classify
reference: url, www.info.com #Reference
priority:1; #Set a priority
metadata: key value, key value; #Extra metadata

# Filter by geolocation
geoip: src,RU;

# ICMP type & Code
itype:<10;
icode:0

# Filter by string
content: "something"
content: |61 61 61| #Hex: AAA
content: "http|3A|//" #Mix string and hex
content: "abc"; nocase; #Case insensitive
reject tcp any any -> any any (msg: "php-rce"; content: "eval"; nocase; metadata: tag php-rce; sid:101; rev: 1;)

# Replaces string
## Content and replace string must have the same length
content:"abc"; replace: "def"
alert tcp any any -> any any (msg: "flag replace"; content: "CTF{a6st"; replace: "CTF{u798"; nocase; sid:100; rev: 1;)
## The replace works in both input and output packets
## But it only modifies the first match

# Filter by regex
pcre:"/<regex>/opts"
pcre:"/NICK .*USA.*[0-9]{3,}/i"
drop tcp any any -> any any (msg:"regex"; pcre:"/CTF\{[\w]{3}/i"; sid:10001;)

# Other examples
## Drop by port
drop tcp any any -> any 8000 (msg:"8000 port"; sid:1000;)
```
<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
