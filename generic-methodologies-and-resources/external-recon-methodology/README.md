# Metodologia de Reconhecimento Externo

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Dica de bug bounty**: **inscreva-se** no **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje mesmo e comece a ganhar recompensas de até **$100.000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Descoberta de Ativos

> Então, disseram a você que tudo que pertence a uma determinada empresa está dentro do escopo, e você quer descobrir o que essa empresa realmente possui.

O objetivo desta fase é obter todas as **empresas pertencentes à empresa principal** e, em seguida, todos os **ativos** dessas empresas. Para fazer isso, vamos:

1. Encontrar as aquisições da empresa principal, isso nos dará as empresas dentro do escopo.
2. Encontrar o ASN (se houver) de cada empresa, isso nos dará os intervalos de IP de propriedade de cada empresa.
3. Usar pesquisas de whois reverso para procurar outras entradas (nomes de organizações, domínios...) relacionadas à primeira (isso pode ser feito recursivamente).
4. Usar outras técnicas como filtros `org` e `ssl` do Shodan para procurar outros ativos (o truque do `ssl` pode ser feito recursivamente).

### **Aquisições**

Antes de mais nada, precisamos saber quais **outras empresas são de propriedade da empresa principal**.\
Uma opção é visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **pesquisar** pela **empresa principal** e **clicar** em "**aquisições**". Lá você verá outras empresas adquiridas pela principal.\
Outra opção é visitar a página do **Wikipedia** da empresa principal e procurar por **aquisições**.

> Ok, neste ponto você deve saber todas as empresas dentro do escopo. Vamos descobrir como encontrar seus ativos.

### **ASNs**

Um número de sistema autônomo (**ASN**) é um **número único** atribuído a um **sistema autônomo** (AS) pela **Internet Assigned Numbers Authority (IANA)**.\
Um **AS** consiste em **blocos** de **endereços IP** que possuem uma política claramente definida para acessar redes externas e são administrados por uma única organização, mas podem ser compostos por vários operadores.

É interessante descobrir se a **empresa possui algum ASN atribuído** para encontrar seus **intervalos de IP**. Será interessante realizar um **teste de vulnerabilidade** em todos os **hosts** dentro do **escopo** e procurar por domínios dentro desses IPs.\
Você pode **pesquisar** pelo nome da empresa, pelo **IP** ou pelo **domínio** em [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Dependendo da região da empresa, esses links podem ser úteis para obter mais dados:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(América do Norte),** [**APNIC**](https://www.apnic.net) **(Ásia),** [**LACNIC**](https://www.lacnic.net) **(América Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De qualquer forma, provavelmente todas as** informações úteis **(intervalos de IP e Whois)** já aparecem no primeiro link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Além disso, a enumeração de subdomínios do [**BBOT**](https://github.com/blacklanternsecurity/bbot) automaticamente agrega e resume os ASNs ao final da varredura.
```bash
bbot -t tesla.com -f subdomain-enum
...
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.244.131.0/24      | 5            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS16509  | 54.148.0.0/15       | 4            | AMAZON-02      | Amazon.com, Inc.           | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.45.124.0/24       | 3            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.32.0.0/12         | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.0.0.0/9           | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+

```
Você pode encontrar os intervalos de IP de uma organização também usando [http://asnlookup.com/](http://asnlookup.com) (ele possui uma API gratuita).\
Você pode encontrar o IP e ASN de um domínio usando [http://ipv4info.com/](http://ipv4info.com).

### **Procurando por vulnerabilidades**

Neste ponto, conhecemos **todos os ativos dentro do escopo**, então, se permitido, você pode executar algum **scanner de vulnerabilidades** (Nessus, OpenVAS) em todos os hosts.\
Além disso, você pode executar algumas [**varreduras de porta**](../pentesting-network/#discovering-hosts-from-the-outside) **ou usar serviços como** shodan **para encontrar** portas abertas **e, dependendo do que encontrar, você deve** consultar este livro para saber como fazer pentest em vários serviços possíveis em execução.\
**Também pode valer a pena mencionar que você também pode preparar algumas** listas de nomes de usuário **e** senhas **padrão e tentar** forçar a entrada em serviços com [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domínios

> Conhecemos todas as empresas dentro do escopo e seus ativos, é hora de encontrar os domínios dentro do escopo.

_Por favor, note que nas técnicas propostas a seguir, você também pode encontrar subdomínios e essas informações não devem ser subestimadas._

Primeiro, você deve procurar o **domínio principal**(is) de cada empresa. Por exemplo, para a _Tesla Inc._ será _tesla.com_.

### **DNS Reverso**

Agora que você encontrou todos os intervalos de IP dos domínios, você pode tentar realizar **pesquisas de DNS reverso** nesses **IPs para encontrar mais domínios dentro do escopo**. Tente usar algum servidor DNS da vítima ou algum servidor DNS conhecido (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que isso funcione, o administrador precisa habilitar manualmente o PTR.\
Você também pode usar uma ferramenta online para obter essas informações: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

Dentro de um **whois**, você pode encontrar muitas informações interessantes, como o **nome da organização**, **endereço**, **emails**, números de telefone... Mas o que é ainda mais interessante é que você pode encontrar **mais ativos relacionados à empresa** se você realizar **pesquisas de reverse whois por qualquer um desses campos** (por exemplo, outros registros de whois onde o mesmo email aparece).\
Você pode usar ferramentas online como:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Grátis**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Grátis**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Grátis**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Grátis** web, não API gratuita.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Não grátis
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Não grátis (apenas **100 pesquisas gratuitas**)
* [https://www.domainiq.com/](https://www.domainiq.com) - Não grátis

Você pode automatizar essa tarefa usando [**DomLink** ](https://github.com/vysecurity/DomLink)(requer uma chave de API do whoxy).\
Você também pode realizar alguma descoberta automática de reverse whois com [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Observe que você pode usar essa técnica para descobrir mais nomes de domínio toda vez que encontrar um novo domínio.**

### **Trackers**

Se você encontrar o **mesmo ID do mesmo rastreador** em 2 páginas diferentes, pode supor que **ambas as páginas** são **gerenciadas pela mesma equipe**.\
Por exemplo, se você ver o mesmo **ID do Google Analytics** ou o mesmo **ID do Adsense** em várias páginas.

Existem algumas páginas e ferramentas que permitem pesquisar por esses rastreadores e mais:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Você sabia que podemos encontrar domínios e subdomínios relacionados ao nosso alvo procurando pelo mesmo hash do ícone do favicon? Isso é exatamente o que a ferramenta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) feita por [@m4ll0k2](https://twitter.com/m4ll0k2) faz. Veja como usá-la:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - descubra domínios com o mesmo hash de ícone de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Simplificando, o favihash nos permitirá descobrir domínios que têm o mesmo hash de ícone de favicon que nosso alvo.

Além disso, você também pode pesquisar tecnologias usando o hash de favicon, conforme explicado neste [**post do blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Isso significa que se você conhece o **hash do favicon de uma versão vulnerável de uma tecnologia web**, você pode pesquisar no shodan e **encontrar mais lugares vulneráveis**:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
Aqui está como você pode **calcular o hash do favicon** de um site:
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url)
favicon = codecs.encode(response.content,"base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
### **Direitos autorais / String única**

Pesquise nas páginas da web **strings que possam ser compartilhadas em diferentes sites da mesma organização**. A **string de direitos autorais** pode ser um bom exemplo. Em seguida, pesquise por essa string no **Google**, em outros **navegadores** ou até mesmo no **Shodan**: `shodan search http.html:"String de direitos autorais"`

### **Tempo do CRT**

É comum ter um trabalho cron, como por exemplo:
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
Para renovar todos os certificados de domínio no servidor. Isso significa que mesmo que a AC usada para isso não defina a hora em que foi gerado no tempo de validade, é possível **encontrar domínios pertencentes à mesma empresa nos logs de transparência de certificados**.\
Confira este [**artigo para mais informações**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### **Apropriação Passiva**

Aparentemente, é comum as pessoas atribuírem subdomínios a IPs que pertencem a provedores de nuvem e, em algum momento, **perderem esse endereço IP, mas esquecerem de remover o registro DNS**. Portanto, apenas **iniciando uma VM** em uma nuvem (como Digital Ocean), você estará realmente **assumindo o controle de alguns subdomínios**.

[**Este post**](https://kmsec.uk/blog/passive-takeover/) explica uma história sobre isso e propõe um script que **inicia uma VM no DigitalOcean**, **obtém** o **IPv4** da nova máquina e **procura no Virustotal por registros de subdomínios** que apontam para ela.

### **Outras maneiras**

**Observe que você pode usar essa técnica para descobrir mais nomes de domínio sempre que encontrar um novo domínio.**

**Shodan**

Como você já sabe o nome da organização que possui o espaço IP, você pode pesquisar por esses dados no Shodan usando: `org:"Tesla, Inc."` Verifique os hosts encontrados em busca de novos domínios inesperados no certificado TLS.

Você pode acessar o **certificado TLS** da página web principal, obter o **nome da organização** e, em seguida, procurar por esse nome nos **certificados TLS** de todas as páginas web conhecidas pelo **Shodan** com o filtro: `ssl:"Tesla Motors"` ou usar uma ferramenta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) é uma ferramenta que procura por **domínios relacionados** a um domínio principal e **subdomínios** deles, muito incrível.

### **Procurando por vulnerabilidades**

Verifique se há algum [apropriação de domínio](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Talvez alguma empresa esteja **usando um domínio**, mas **perdeu a propriedade**. Basta registrá-lo (se for barato o suficiente) e informar a empresa.

Se você encontrar algum **domínio com um IP diferente** dos que já encontrou na descoberta de ativos, você deve realizar uma **varredura básica de vulnerabilidades** (usando Nessus ou OpenVAS) e uma [**varredura de portas**](../pentesting-network/#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo dos serviços em execução, você pode encontrar neste livro alguns truques para "atacá-los".\
Observe que às vezes o domínio está hospedado em um IP que não é controlado pelo cliente, portanto, não está no escopo, tenha cuidado.

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Dica de bug bounty**: **inscreva-se** no **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje mesmo e comece a ganhar recompensas de até **$100.000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdomínios

> Sabemos todas as empresas dentro do escopo, todos os ativos de cada empresa e todos os domínios relacionados às empresas.

É hora de encontrar todos os possíveis subdomínios de cada domínio encontrado.

### **DNS**

Vamos tentar obter **subdomínios** dos registros **DNS**. Também devemos tentar a **Transferência de Zona** (Se vulnerável, você deve relatar isso).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

A maneira mais rápida de obter muitos subdomínios é pesquisar em fontes externas. As ferramentas mais usadas são as seguintes (para obter melhores resultados, configure as chaves da API):

* [**BBOT**](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```
* [**Amass**](https://github.com/OWASP/Amass)
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```
* [**subfinder**](https://github.com/projectdiscovery/subfinder)
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```
* [**findomain**](https://github.com/Edu4rdSHL/findomain/)

O **findomain** é uma ferramenta de reconhecimento externo que pode ser usada para encontrar subdomínios de um determinado domínio. Ele usa uma abordagem de pesquisa passiva, consultando registros públicos e fontes de dados disponíveis para descobrir subdomínios. Essa ferramenta é útil para hackers éticos e profissionais de segurança que desejam identificar possíveis pontos de entrada em um sistema. O **findomain** é uma opção eficaz para realizar uma análise inicial de um alvo antes de prosseguir com testes de penetração mais avançados.
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/pt-br)

OneForAll é uma ferramenta de reconhecimento externo que automatiza a coleta de informações sobre um alvo. Ele utiliza várias fontes públicas, como motores de busca, registros de domínio, certificados SSL e muito mais, para obter informações valiosas sobre o alvo.

A metodologia de reconhecimento externo usando o OneForAll pode ser dividida em várias etapas:

1. **Coleta de informações**: Nesta etapa, o OneForAll coleta informações básicas sobre o alvo, como endereços IP, domínios e subdomínios.

2. **Ampliação de informações**: O OneForAll utiliza várias técnicas para ampliar as informações coletadas na etapa anterior. Isso inclui a busca de registros de domínio, certificados SSL, endereços de e-mail e muito mais.

3. **Análise de informações**: Nesta etapa, o OneForAll analisa as informações coletadas e as organiza de forma a fornecer uma visão clara do alvo. Isso inclui a identificação de possíveis vulnerabilidades e pontos fracos.

4. **Relatório de informações**: O OneForAll gera um relatório detalhado das informações coletadas, que pode ser usado para análise posterior ou para auxiliar em testes de penetração.

O OneForAll é uma ferramenta poderosa que pode ajudar os hackers éticos a obter informações valiosas sobre um alvo. No entanto, é importante lembrar que o uso indevido dessa ferramenta pode ser ilegal e antiético. Portanto, é essencial usá-la apenas para fins legítimos, como testes de penetração autorizados.
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
* [**assetfinder**](https://github.com/tomnomnom/assetfinder)

O **assetfinder** é uma ferramenta de reconhecimento externo desenvolvida por tomnomnom. Ela é usada para descobrir ativos de um alvo específico, como subdomínios, endereços IP e outros recursos relacionados. Essa ferramenta é útil para hackers e profissionais de segurança que desejam obter informações sobre a infraestrutura de um alvo antes de realizar um teste de invasão ou uma avaliação de segurança. O **assetfinder** é uma opção eficaz para realizar uma coleta inicial de informações e pode ser integrado a outras ferramentas e scripts para obter resultados mais abrangentes.
```bash
assetfinder --subs-only <domain>
```
* [**Sudomy**](https://github.com/Screetsec/Sudomy)
```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```
* [**vita**](https://github.com/junnlikestea/vita)
```
vita -d tesla.com
```
* [**theHarvester**](https://github.com/laramies/theHarvester)
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
Existem **outras ferramentas/APIs interessantes** que, mesmo não sendo diretamente especializadas em encontrar subdomínios, podem ser úteis para encontrá-los, como:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Utiliza a API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obter subdomínios.
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**API gratuita JLDC**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) API gratuito
```bash
# Get Domains from rapiddns free API
rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
rapiddns tesla.com
```
* [**https://crt.sh/**](https://crt.sh)
```bash
# Get Domains from crt free API
crt(){
curl -s "https://crt.sh/?q=%25.$1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
crt tesla.com
```
* [**gau**](https://github.com/lc/gau)**:** recupera URLs conhecidas do AlienVault's Open Threat Exchange, do Wayback Machine e do Common Crawl para qualquer domínio fornecido.
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Eles vasculham a web em busca de arquivos JS e extraem subdomínios a partir deles.
```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```
* [**Shodan**](https://www.shodan.io/)

Shodan is a search engine that allows you to find specific types of devices connected to the internet. It is particularly useful for conducting external reconnaissance as it can help you identify vulnerable systems, open ports, and other valuable information. Shodan can be used to search for a wide range of devices, including webcams, routers, servers, and even industrial control systems. By using specific search queries, you can narrow down your results and find devices that may be of interest for further investigation. Shodan also provides additional features such as the ability to view historical data and monitor changes in device configurations over time.
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
* [**Censys subdomain finder**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) possui uma API gratuita para pesquisar subdomínios e histórico de IP
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Este projeto oferece gratuitamente todos os subdomínios relacionados a programas de recompensa por bugs. Você também pode acessar esses dados usando [chaospy](https://github.com/dr-0x0x/chaospy) ou até mesmo acessar o escopo usado por este projeto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Você pode encontrar uma **comparação** de muitas dessas ferramentas aqui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Vamos tentar encontrar novos subdomínios forçando servidores DNS usando possíveis nomes de subdomínio.

Para essa ação, você precisará de algumas **listas de palavras comuns de subdomínios, como**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E também IPs de bons resolvedores DNS. Para gerar uma lista de resolvedores DNS confiáveis, você pode baixar os resolvedores de [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) e usar o [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrá-los. Ou você pode usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

As ferramentas mais recomendadas para brute-force DNS são:

* [**massdns**](https://github.com/blechschmidt/massdns): Esta foi a primeira ferramenta que realizou um brute-force DNS efetivo. É muito rápido, no entanto, está sujeito a falsos positivos.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Acredito que este utilize apenas 1 resolvedor.
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) é um wrapper em torno do `massdns`, escrito em go, que permite enumerar subdomínios válidos usando brute force ativo, além de resolver subdomínios com tratamento de wildcards e suporte fácil de entrada e saída.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Ele também utiliza o `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utiliza asyncio para forçar nomes de domínio de forma assíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda Rodada de Brute-Force DNS

Após ter encontrado subdomínios usando fontes abertas e brute-forcing, você pode gerar alterações dos subdomínios encontrados para tentar encontrar ainda mais. Várias ferramentas são úteis para esse propósito:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dado os domínios e subdomínios, gera permutações.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Dado os domínios e subdomínios, gera permutações.
* Você pode obter a lista de permutações do goaltdns **wordlist** [**aqui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Dado os domínios e subdomínios, gera permutações. Se nenhum arquivo de permutações for indicado, o gotator usará o próprio arquivo.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Além de gerar permutações de subdomínios, também pode tentar resolvê-los (mas é melhor usar as ferramentas comentadas anteriormente).
* Você pode obter a lista de permutações do altdns **wordlist** [**aqui**](https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Outra ferramenta para realizar permutações, mutações e alterações de subdomínios. Essa ferramenta irá forçar bruta o resultado (ela não suporta curinga dns).
* Você pode obter a lista de palavras de permutações do dmut [**aqui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Com base em um domínio, ele **gera novos nomes potenciais de subdomínios** com base em padrões indicados para tentar descobrir mais subdomínios.

#### Geração inteligente de permutações

* [**regulator**](https://github.com/cramppet/regulator): Para mais informações, leia este [**post**](https://cramppet.github.io/regulator/index.html), mas basicamente ele irá obter as **partes principais** dos **subdomínios descobertos** e irá misturá-las para encontrar mais subdomínios.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ é um fuzzer de brute-force de subdomínio acoplado a um algoritmo de resposta DNS extremamente simples, mas eficaz. Ele utiliza um conjunto fornecido de dados de entrada, como uma lista de palavras personalizada ou registros históricos de DNS/TLS, para sintetizar com precisão mais nomes de domínio correspondentes e expandi-los ainda mais em um loop com base nas informações coletadas durante a varredura DNS.
```
echo www | subzuf facebook.com
```
### **Fluxo de Descoberta de Subdomínios**

Confira este post no blog que escrevi sobre como **automatizar a descoberta de subdomínios** de um domínio usando **fluxos de trabalho Trickest** para que eu não precise executar manualmente um monte de ferramentas no meu computador:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Virtual Hosts**

Se você encontrou um endereço IP contendo **uma ou várias páginas da web** pertencentes a subdomínios, você pode tentar **encontrar outros subdomínios com sites nesse IP** procurando em **fontes de OSINT** por domínios em um IP ou **forçando nomes de domínio VHost nesse IP**.

#### OSINT

Você pode encontrar alguns **VHosts em IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou outras APIs**.

**Força Bruta**

Se você suspeita que algum subdomínio possa estar oculto em um servidor web, você pode tentar forçar a sua descoberta:
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
{% hint style="info" %}
Com essa técnica, você pode até mesmo conseguir acessar endpoints internos/ocultos.
{% endhint %}

### **Força Bruta de CORS**

Às vezes, você encontrará páginas que retornam apenas o cabeçalho _**Access-Control-Allow-Origin**_ quando um domínio/subdomínio válido é definido no cabeçalho _**Origin**_. Nessas situações, você pode abusar desse comportamento para **descobrir** novos **subdomínios**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Força Bruta de Buckets**

Ao procurar por **subdomínios**, fique atento para ver se eles estão **apontando** para algum tipo de **bucket**, e nesse caso [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Além disso, agora que você conhece todos os domínios dentro do escopo, tente [**forçar possíveis nomes de buckets e verificar as permissões**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitoramento**

Você pode **monitorar** se novos **subdomínios** de um domínio são criados monitorando os **Logs de Transparência de Certificado** que o [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) faz.

### **Procurando por vulnerabilidades**

Verifique possíveis [**apropriações de subdomínio**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se o **subdomínio** estiver apontando para algum **bucket S3**, [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/).

Se você encontrar algum **subdomínio com um IP diferente** dos que você já encontrou na descoberta de ativos, você deve realizar uma **varredura básica de vulnerabilidades** (usando Nessus ou OpenVAS) e uma [**varredura de portas**](../pentesting-network/#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo dos serviços em execução, você pode encontrar neste livro alguns truques para "atacá-los".\
Observe que às vezes o subdomínio está hospedado em um IP que não é controlado pelo cliente, portanto, não está no escopo, tenha cuidado.

## IPs

Nas etapas iniciais, você pode ter **encontrado alguns intervalos de IP, domínios e subdomínios**.\
É hora de **recolher todos os IPs desses intervalos** e dos **domínios/subdomínios (consultas DNS)**.

Usando serviços das seguintes **APIs gratuitas**, você também pode encontrar **IPs anteriores usados por domínios e subdomínios**. Esses IPs ainda podem ser de propriedade do cliente (e podem permitir que você encontre [**bypasses do CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

Você também pode verificar os domínios que apontam para um endereço IP específico usando a ferramenta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Procurando por vulnerabilidades**

**Varredure todas as IPs que não pertencem a CDNs** (pois você provavelmente não encontrará nada interessante nelas). Nos serviços em execução descobertos, você pode ser **capaz de encontrar vulnerabilidades**.

**Encontre um** [**guia**](../pentesting-network/) **sobre como escanear hosts**.

## Caça a servidores web

> Encontramos todas as empresas e seus ativos e conhecemos os intervalos de IP, domínios e subdomínios dentro do escopo. É hora de procurar por servidores web.

Nas etapas anteriores, você provavelmente já realizou alguma **reconhecimento dos IPs e domínios descobertos**, então você pode ter **encontrado todos os possíveis servidores web**. No entanto, se você ainda não encontrou, agora vamos ver alguns **truques rápidos para procurar servidores web** dentro do escopo.

Por favor, observe que isso será **orientado para a descoberta de aplicativos web**, então você deve **realizar a varredura de vulnerabilidades** e **port scanning** também (**se permitido** pelo escopo).

Um **método rápido** para descobrir **portas abertas** relacionadas a **servidores web** usando o [**masscan pode ser encontrado aqui**](../pentesting-network/#http-port-discovery).\
Outra ferramenta útil para procurar servidores web é o [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Basta passar uma lista de domínios e ele tentará se conectar à porta 80 (http) e 443 (https). Além disso, você pode indicar para tentar outras portas:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Capturas de tela**

Agora que você descobriu **todos os servidores web** presentes no escopo (entre os **IPs** da empresa e todos os **domínios** e **subdomínios**), provavelmente **não sabe por onde começar**. Então, vamos simplificar e começar apenas tirando capturas de tela de todos eles. Apenas **dando uma olhada** na **página principal**, você pode encontrar endpoints **estranhos** que são mais **propensos** a serem **vulneráveis**.

Para realizar a ideia proposta, você pode usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Além disso, você pode usar o [**eyeballer**](https://github.com/BishopFox/eyeballer) para percorrer todas as **capturas de tela** e informar quais são **propensas a conter vulnerabilidades** e quais não são.

## Ativos em Nuvem Pública

Para encontrar possíveis ativos em nuvem pertencentes a uma empresa, você deve **começar com uma lista de palavras-chave que identifiquem essa empresa**. Por exemplo, para uma empresa de criptomoedas, você pode usar palavras como: `"crypto", "wallet", "dao", "<nome_do_domínio>", <"nomes_de_subdomínio">`.

Você também precisará de listas de palavras comuns usadas em buckets:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Em seguida, com essas palavras, você deve gerar **permutações** (verifique a seção [**Segunda Rodada de Brute-Force DNS**](./#second-dns-bruteforce-round) para mais informações).

Com as listas de palavras resultantes, você pode usar ferramentas como [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Lembre-se de que, ao procurar Ativos em Nuvem, você deve procurar **mais do que apenas buckets na AWS**.

### **Procurando por vulnerabilidades**

Se você encontrar coisas como **buckets abertos ou funções em nuvem expostas**, você deve **acessá-los** e tentar ver o que eles oferecem e se você pode abusar deles.

## E-mails

Com os **domínios** e **subdomínios** dentro do escopo, você basicamente tem tudo o que **precisa para começar a procurar por e-mails**. Estas são as **APIs** e **ferramentas** que funcionaram melhor para mim na busca por e-mails de uma empresa:

* [**theHarvester**](https://github.com/laramies/theHarvester) - com APIs
* API do [**https://hunter.io/**](https://hunter.io/) (versão gratuita)
* API do [**https://app.snov.io/**](https://app.snov.io/) (versão gratuita)
* API do [**https://minelead.io/**](https://minelead.io/) (versão gratuita)

### **Procurando por vulnerabilidades**

Os e-mails serão úteis posteriormente para **brute-force em logins web e serviços de autenticação** (como SSH). Além disso, eles são necessários para **phishings**. Além disso, essas APIs fornecerão ainda mais **informações sobre a pessoa** por trás do e-mail, o que é útil para a campanha de phishing.

## Vazamentos de Credenciais

Com os **domínios**, **subdomínios** e **e-mails**, você pode começar a procurar por credenciais vazadas no passado pertencentes a esses e-mails:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Procurando por vulnerabilidades**

Se você encontrar credenciais vazadas **válidas**, essa é uma vitória muito fácil.

## Vazamentos de Segredos

Vazamentos de credenciais estão relacionados a ataques a empresas onde **informações sensíveis foram vazadas e vendidas**. No entanto, as empresas podem ser afetadas por **outros vazamentos** cujas informações não estão nesses bancos de dados:

### Vazamentos no Github

Credenciais e APIs podem ser vazadas nos **repositórios públicos** da **empresa** ou dos **usuários** que trabalham para essa empresa no Github.\
Você pode usar a **ferramenta** [**Leakos**](https://github.com/carlospolop/Leakos) para **baixar** todos os **repositórios públicos** de uma **organização** e de seus **desenvolvedores** e executar automaticamente o [**gitleaks**](https://github.com/zricethezav/gitleaks) neles.

O **Leakos** também pode ser usado para executar o **gitleaks** em todas as **URLs de texto** fornecidas a ele, pois às vezes as **páginas da web também contêm segredos**.

#### Github Dorks

Verifique também esta **página** para possíveis **github dorks** que você também pode pesquisar na organização que está atacando:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Vazamentos em Pastes

Às vezes, atacantes ou apenas funcionários irão **publicar conteúdo da empresa em um site de paste**. Isso pode ou não conter **informações sensíveis**, mas é muito interessante procurar por isso.\
Você pode usar a ferramenta [**Pastos**](https://github.com/carlospolop/Pastos) para pesquisar em mais de 80 sites de paste ao mesmo tempo.

### Google Dorks

Google dorks antigos, mas úteis, são sempre úteis para encontrar **informações expostas que não deveriam estar lá**. O único problema é que o [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contém vários **milhares** de consultas possíveis que você não pode executar manualmente. Portanto, você pode escolher suas 10 favoritas ou usar uma **ferramenta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para executá-las todas**.

Observe que as ferramentas que esperam executar todo o banco de dados usando o navegador regular do Google nunca terminarão, pois o Google bloqueará você muito em breve.
### **Procurando vulnerabilidades**

Se você encontrar credenciais ou tokens de API **vazados e válidos**, isso é uma vitória muito fácil.

## Vulnerabilidades de Código Público

Se você descobrir que a empresa possui **código aberto**, você pode **analisá-lo** e procurar **vulnerabilidades** nele.

**Dependendo da linguagem**, existem diferentes **ferramentas** que você pode usar:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Também existem serviços gratuitos que permitem **escanear repositórios públicos**, como:

* [**Snyk**](https://app.snyk.io/)

## [**Metodologia de Teste de Penetração Web**](../../network-services-pentesting/pentesting-web/)

A **maioria das vulnerabilidades** encontradas por caçadores de bugs estão dentro de **aplicações web**, então neste ponto eu gostaria de falar sobre uma **metodologia de teste de aplicação web**, e você pode [**encontrar essas informações aqui**](../../network-services-pentesting/pentesting-web/).

Também quero fazer uma menção especial à seção [**Ferramentas de Scanner Automático de Web de Código Aberto**](../../network-services-pentesting/pentesting-web/#automatic-scanners), pois, embora você não deva esperar que elas encontrem vulnerabilidades muito sensíveis, elas são úteis para implementá-las em **fluxos de trabalho para obter algumas informações web iniciais**.

## Recapitulação

> Parabéns! Neste ponto, você já realizou **toda a enumeração básica**. Sim, é básica porque ainda há muito mais enumeração a ser feita (veremos mais truques depois).

Então você já:

1. Encontrou todas as **empresas** dentro do escopo.
2. Encontrou todos os **ativos** pertencentes às empresas (e realizou uma varredura de vulnerabilidades, se estiver no escopo).
3. Encontrou todos os **domínios** pertencentes às empresas.
4. Encontrou todos os **subdomínios** dos domínios (algum subdomínio pode ser assumido?).
5. Encontrou todos os **IPs** (de e **não de CDNs**) dentro do escopo.
6. Encontrou todos os **servidores web** e tirou uma **captura de tela** deles (algo estranho que valha uma investigação mais aprofundada?).
7. Encontrou todos os **ativos potenciais de nuvem pública** pertencentes à empresa.
8. **E-mails**, **vazamentos de credenciais** e **vazamentos de segredos** que podem lhe dar uma **grande vitória facilmente**.
9. **Testou todas as aplicações web** que você encontrou.

## **Ferramentas Automáticas de Reconhecimento Completo**

Existem várias ferramentas disponíveis que executarão parte das ações propostas em um escopo específico.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Um pouco antigo e não atualizado

## **Referências**

* **Todos os cursos gratuitos de** [**@Jhaddix**](https://twitter.com/Jhaddix) **(como** [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)**)**

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Dica de bug bounty**: **inscreva-se** no **Intigriti**, uma plataforma premium de **bug bounty criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje mesmo e comece a ganhar recompensas de até **$100.000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo Telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
