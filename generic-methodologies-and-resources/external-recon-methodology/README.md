# Metodologia de Reconhecimento Externo

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira [**produtos oficiais PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se você está interessado em **carreira de hacking** e hackear o inhackeável - **estamos contratando!** (_fluência em polonês escrita e falada necessária_).

{% embed url="https://www.stmcyber.com/careers" %}

## Descoberta de Ativos

> Então disseram a você que tudo pertencente a uma empresa está dentro do escopo, e você quer descobrir o que essa empresa realmente possui.

O objetivo desta fase é obter todas as **empresas pertencentes à empresa principal** e, em seguida, todos os **ativos** dessas empresas. Para fazer isso, vamos:

1. Encontrar as aquisições da empresa principal, isso nos dará as empresas dentro do escopo.
2. Encontrar o ASN (se houver) de cada empresa, isso nos dará os intervalos de IP de propriedade de cada empresa.
3. Usar pesquisas de whois reverso para procurar outras entradas (nomes de organizações, domínios...) relacionadas à primeira (isso pode ser feito de forma recursiva).
4. Usar outras técnicas como filtros `org` e `ssl` do shodan para procurar outros ativos (o truque `ssl` pode ser feito de forma recursiva).

### **Aquisições**

Antes de tudo, precisamos saber quais **outras empresas são de propriedade da empresa principal**.\
Uma opção é visitar [https://www.crunchbase.com/](https://www.crunchbase.com), **pesquisar** pela **empresa principal** e **clicar** em "**aquisições**". Lá você verá outras empresas adquiridas pela principal.\
Outra opção é visitar a página da **Wikipedia** da empresa principal e procurar por **aquisições**.

> Ok, neste ponto você deve saber todas as empresas dentro do escopo. Vamos descobrir como encontrar seus ativos.

### **ASNs**

Um número de sistema autônomo (**ASN**) é um **número único** atribuído a um **sistema autônomo** (AS) pela **Internet Assigned Numbers Authority (IANA)**.\
Um **AS** consiste em **blocos** de **endereços IP** que possuem uma política claramente definida para acessar redes externas e são administrados por uma única organização, mas podem ser compostos por vários operadores.

É interessante descobrir se a **empresa possui algum ASN atribuído** para encontrar seus **intervalos de IP**. Será interessante realizar um **teste de vulnerabilidade** contra todos os **hosts** dentro do **escopo** e procurar **domínios** dentro desses IPs.\
Você pode **pesquisar** pelo nome da empresa, pelo **IP** ou pelo **domínio** em [**https://bgp.he.net/**](https://bgp.he.net)**.**\
**Dependendo da região da empresa, esses links podem ser úteis para reunir mais dados:** [**AFRINIC**](https://www.afrinic.net) **(África),** [**Arin**](https://www.arin.net/about/welcome/region/)**(América do Norte),** [**APNIC**](https://www.apnic.net) **(Ásia),** [**LACNIC**](https://www.lacnic.net) **(América Latina),** [**RIPE NCC**](https://www.ripe.net) **(Europa). De qualquer forma, provavelmente todas as** informações úteis **(intervalos de IP e Whois)** já aparecem no primeiro link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
Também, a enumeração de subdomínios do [**BBOT**](https://github.com/blacklanternsecurity/bbot) automaticamente agrega e resume ASNs no final da varredura.
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
Pode encontrar os intervalos de IP de uma organização também usando [http://asnlookup.com/](http://asnlookup.com) (tem uma API gratuita).\
Pode encontrar o IP e ASN de um domínio usando [http://ipv4info.com/](http://ipv4info.com).

### **Procurando por vulnerabilidades**

Neste ponto, conhecemos **todos os ativos dentro do escopo**, então, se permitido, você pode executar algum **scanner de vulnerabilidades** (Nessus, OpenVAS) em todos os hosts.\
Também, você pode executar alguns [**scans de porta**](../pentesting-network/#discovering-hosts-from-the-outside) **ou usar serviços como** shodan **para encontrar** portas abertas **e, dependendo do que encontrar, você deve** consultar este livro para saber como fazer pentest em vários serviços possíveis em execução.\
**Além disso, vale mencionar que você também pode preparar algumas** listas de nomes de usuário **e** senhas **padrão e tentar** forçar a entrada em serviços com [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domínios

> Conhecemos todas as empresas dentro do escopo e seus ativos, é hora de encontrar os domínios dentro do escopo.

_Por favor, note que nas técnicas propostas a seguir você também pode encontrar subdomínios e essa informação não deve ser subestimada._

Primeiramente, você deve procurar o(s) **domínio(s) principal(is)** de cada empresa. Por exemplo, para a _Tesla Inc._ será _tesla.com_.

### **DNS Reverso**

Como você encontrou todos os intervalos de IP dos domínios, você pode tentar realizar **consultas de DNS reverso** nesses **IPs para encontrar mais domínios dentro do escopo**. Tente usar algum servidor DNS da vítima ou algum servidor DNS conhecido (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
Para que isso funcione, o administrador precisa habilitar manualmente o PTR.\
Você também pode usar uma ferramenta online para essa informação: [http://ptrarchive.com/](http://ptrarchive.com)

### **Reverse Whois (loop)**

Dentro de um **whois**, você pode encontrar muitas informações interessantes, como o **nome da organização**, **endereço**, **e-mails**, números de telefone... Mas o que é ainda mais interessante é que você pode encontrar **mais ativos relacionados à empresa** se você realizar **pesquisas de reverse whois por qualquer um desses campos** (por exemplo, outros registros whois onde o mesmo e-mail aparece).\
Você pode usar ferramentas online como:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Grátis**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Grátis**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **Grátis**
* [https://www.whoxy.com/](https://www.whoxy.com) - **Grátis** na web, não grátis na API.
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Não grátis
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Não grátis (apenas **100 pesquisas gratuitas**)
* [https://www.domainiq.com/](https://www.domainiq.com) - Não grátis

Você pode automatizar essa tarefa usando [**DomLink** ](https://github.com/vysecurity/DomLink)(requer uma chave de API whoxy).\
Você também pode realizar alguma descoberta automática de reverse whois com [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`

**Observe que você pode usar essa técnica para descobrir mais nomes de domínio toda vez que encontrar um novo domínio.**

### **Trackers**

Se encontrar o **mesmo ID do mesmo tracker** em 2 páginas diferentes, você pode supor que **ambas as páginas** são **gerenciadas pela mesma equipe**.\
Por exemplo, se você ver o mesmo **ID do Google Analytics** ou o mesmo **ID do Adsense** em várias páginas.

Existem algumas páginas e ferramentas que permitem pesquisar por esses trackers e mais:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

Você sabia que podemos encontrar domínios e subdomínios relacionados ao nosso alvo procurando pelo mesmo hash do ícone do favicon? É exatamente isso que a ferramenta [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) feita por [@m4ll0k2](https://twitter.com/m4ll0k2) faz. Veja como usá-la:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - descubra domínios com o mesmo hash de ícone de favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Simplesmente dito, o favihash nos permitirá descobrir domínios que têm o mesmo hash de ícone de favicon que nosso alvo.

Além disso, você também pode pesquisar tecnologias usando o hash de favicon, conforme explicado neste [**post de blog**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139). Isso significa que se você conhece o **hash do favicon de uma versão vulnerável de uma tecnologia web**, você pode pesquisar no shodan e **encontrar mais lugares vulneráveis**:
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
### **Direitos autorais / String exclusiva**

Pesquise nas páginas da web **strings que podem ser compartilhadas em diferentes sites na mesma organização**. A **string de direitos autorais** poderia ser um bom exemplo. Em seguida, pesquise essa string no **Google**, em outros **navegadores** ou até mesmo no **Shodan**: `shodan search http.html:"String de direitos autorais"`

### **Tempo CRT**

É comum ter um trabalho cron, como
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
### Metodologia de Reconhecimento Externo

Para renovar todos os certificados de domínio no servidor. Isso significa que mesmo que a AC usada para isso não defina a hora em que foi gerado no tempo de Validade, é possível **encontrar domínios pertencentes à mesma empresa nos logs de transparência do certificado**.\
Confira este [**artigo para mais informações**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

### **Assunção Passiva**

Aparentemente, é comum as pessoas atribuírem subdomínios a IPs que pertencem a provedores de nuvem e, em algum momento, **perderem esse endereço IP, mas esquecerem de remover o registro DNS**. Portanto, apenas **iniciando uma VM** em uma nuvem (como Digital Ocean), você estará realmente **assumindo o controle de alguns subdomínios**.

[**Este post**](https://kmsec.uk/blog/passive-takeover/) explica uma história sobre isso e propõe um script que **inicia uma VM na DigitalOcean**, **obtém** o **IPv4** da nova máquina e **pesquisa no Virustotal por registros de subdomínios** apontando para ele.

### **Outras maneiras**

**Observe que você pode usar essa técnica para descobrir mais nomes de domínio toda vez que encontrar um novo domínio.**

**Shodan**

Como você já sabe o nome da organização que possui o espaço IP. Você pode pesquisar por esses dados no Shodan usando: `org:"Tesla, Inc."` Verifique os hosts encontrados em busca de novos domínios inesperados no certificado TLS.

Você poderia acessar o **certificado TLS** da página web principal, obter o **nome da organização** e então procurar por esse nome dentro dos **certificados TLS** de todas as páginas web conhecidas pelo **Shodan** com o filtro: `ssl:"Tesla Motors"` ou usar uma ferramenta como [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) é uma ferramenta que procura por **domínios relacionados** com um domínio principal e **subdomínios** deles, muito incrível.

### **Procurando por vulnerabilidades**

Verifique por algum [domínio assumido](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Talvez alguma empresa esteja **usando um domínio** mas tenha **perdido a propriedade**. Apenas registre-o (se for barato o suficiente) e avise a empresa.

Se você encontrar algum **domínio com um IP diferente** dos que você já encontrou na descoberta de ativos, você deve realizar uma **varredura de vulnerabilidades básica** (usando Nessus ou OpenVAS) e alguma [**varredura de porta**](../pentesting-network/#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo de quais serviços estão em execução, você pode encontrar neste livro alguns truques para "atacá-los".\
_Obs.: Às vezes, o domínio está hospedado dentro de um IP que não é controlado pelo cliente, então não está no escopo, tenha cuidado._

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Dica de recompensa por bugs**: **inscreva-se** no **Intigriti**, uma plataforma de **recompensas por bugs premium criada por hackers, para hackers**! Junte-se a nós em [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoje e comece a ganhar recompensas de até **$100.000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Subdomínios

> Sabemos todas as empresas dentro do escopo, todos os ativos de cada empresa e todos os domínios relacionados às empresas.

É hora de encontrar todos os possíveis subdomínios de cada domínio encontrado.

### **DNS**

Vamos tentar obter **subdomínios** dos **registros DNS**. Também devemos tentar a **Transferência de Zona** (Se vulnerável, você deve relatar).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

A maneira mais rápida de obter muitos subdomínios é pesquisar em fontes externas. As **ferramentas** mais utilizadas são as seguintes (para obter melhores resultados, configure as chaves da API):

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
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
* [**assetfinder**](https://github.com/tomnomnom/assetfinder)
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
Existem **outras ferramentas/APIs interessantes** que, mesmo que não sejam diretamente especializadas em encontrar subdomínios, podem ser úteis para encontrar subdomínios, como:

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** Utiliza a API [https://sonar.omnisint.io](https://sonar.omnisint.io) para obter subdomínios
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
* [**gau**](https://github.com/lc/gau)**:** recupera URLs conhecidos do Open Threat Exchange da AlienVault, do Wayback Machine e do Common Crawl para qualquer domínio fornecido.
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
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
* [**Localizador de subdomínios Censys**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) tem uma API gratuita para pesquisar subdomínios e histórico de IP
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

Este projeto oferece de **forma gratuita todos os subdomínios relacionados aos programas de recompensa por bugs**. Você pode acessar esses dados também usando [chaospy](https://github.com/dr-0x0x/chaospy) ou até mesmo acessar o escopo usado por este projeto [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

Você pode encontrar uma **comparação** de muitas dessas ferramentas aqui: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Vamos tentar encontrar novos **subdomínios** forçando servidores DNS usando possíveis nomes de subdomínio.

Para esta ação, você precisará de algumas **listas de palavras comuns de subdomínios como**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

E também IPs de bons resolvedores de DNS. Para gerar uma lista de resolvedores de DNS confiáveis, você pode baixar os resolvedores de [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) e usar [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) para filtrá-los. Ou você poderia usar: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

As ferramentas mais recomendadas para brute force de DNS são:

* [**massdns**](https://github.com/blechschmidt/massdns): Esta foi a primeira ferramenta que realizou um brute force de DNS eficaz. É muito rápido, no entanto, está sujeito a falsos positivos.
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): Eu acho que este usa apenas 1 resolvedor
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) é um wrapper em `massdns`, escrito em go, que permite enumerar subdomínios válidos usando força bruta ativa, além de resolver subdomínios com tratamento de curinga e suporte fácil de entrada e saída.
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): Também utiliza o `massdns`.
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) utiliza asyncio para forçar nomes de domínio de forma assíncrona.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Segunda Rodada de Força Bruta no DNS

Após encontrar subdomínios usando fontes abertas e força bruta, você pode gerar alterações nos subdomínios encontrados para tentar encontrar ainda mais. Várias ferramentas são úteis para esse propósito:

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** Dado os domínios e subdomínios, gera permutações.
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): Dado os domínios e subdomínios, gera permutações.
* Você pode obter a lista de permutações do goaltdns **wordlist** [**aqui**](https://github.com/subfinder/goaltdns/blob/master/words.txt).
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** Dado os domínios e subdomínios, gera permutações. Se nenhum arquivo de permutações for indicado, o gotator usará o seu próprio.
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): Além de gerar permutações de subdomínios, também pode tentar resolvê-los (mas é melhor usar as ferramentas comentadas anteriormente).
* Você pode obter a lista de palavras de permutação do altdns **aqui** (https://github.com/infosec-au/altdns/blob/master/words.txt).
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): Outra ferramenta para realizar permutações, mutações e alterações de subdomínios. Esta ferramenta fará força bruta no resultado (não suporta curinga dns).
* Você pode obter a lista de palavras de permutações do dmut [**aqui**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** Com base em um domínio, **gera novos nomes potenciais de subdomínios** com base em padrões indicados para tentar descobrir mais subdomínios.

#### Geração inteligente de permutações

* [**regulator**](https://github.com/cramppet/regulator): Para mais informações, leia este [**post**](https://cramppet.github.io/regulator/index.html), mas basicamente ele irá obter as **partes principais** dos **subdomínios descobertos** e irá misturá-las para encontrar mais subdomínios.
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ é um fuzzer de força bruta de subdomínio acoplado a um algoritmo imensamente simples, mas eficaz, guiado por respostas DNS. Ele utiliza um conjunto fornecido de dados de entrada, como uma lista de palavras personalizada ou registros históricos de DNS/TLS, para sintetizar com precisão mais nomes de domínio correspondentes e expandi-los ainda mais em um loop com base nas informações coletadas durante a varredura DNS.
```
echo www | subzuf facebook.com
```
### **Fluxo de Descoberta de Subdomínio**

Confira este post no blog que escrevi sobre como **automatizar a descoberta de subdomínios** de um domínio usando **fluxos de trabalho Trickest** para que eu não precise iniciar manualmente um monte de ferramentas no meu computador:

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / Hosts Virtuais**

Se você encontrou um endereço IP contendo **uma ou várias páginas da web** pertencentes a subdomínios, você pode tentar **encontrar outros subdomínios com páginas naquele IP** procurando em **fontes de OSINT** por domínios em um IP ou **forçando bruta-mente nomes de domínio VHost naquele IP**.

#### OSINT

Você pode encontrar alguns **VHosts em IPs usando** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **ou outras APIs**.

**Força Bruta**

Se você suspeitar que algum subdomínio pode estar oculto em um servidor web, você pode tentar forçar bruta-mente:
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
Com esta técnica, você pode até mesmo ser capaz de acessar endpoints internos/ocultos.
{% endhint %}

### **Força Bruta de CORS**

Às vezes, você encontrará páginas que só retornam o cabeçalho _**Access-Control-Allow-Origin**_ quando um domínio/subdomínio válido é definido no cabeçalho _**Origin**_. Nestes cenários, você pode abusar desse comportamento para **descobrir** novos **subdomínios**.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Forçar Buckets**

Ao procurar por **subdomínios**, fique atento para ver se ele está **apontando** para algum tipo de **bucket**, e nesse caso [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/)**.**\
Além disso, neste ponto, você conhecerá todos os domínios dentro do escopo, tente [**forçar possíveis nomes de buckets e verificar as permissões**](../../network-services-pentesting/pentesting-web/buckets/).

### **Monitoramento**

Você pode **monitorar** se **novos subdomínios** de um domínio são criados monitorando os **Logs de Transparência de Certificado** que o [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) faz.

### **Procurando por vulnerabilidades**

Verifique possíveis [**apropriações de subdomínio**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Se o **subdomínio** estiver apontando para algum **bucket S3**, [**verifique as permissões**](../../network-services-pentesting/pentesting-web/buckets/).

Se você encontrar algum **subdomínio com um IP diferente** dos que você já encontrou na descoberta de ativos, você deve realizar uma **varredura de vulnerabilidade básica** (usando Nessus ou OpenVAS) e alguma [**varredura de porta**](../pentesting-network/#discovering-hosts-from-the-outside) com **nmap/masscan/shodan**. Dependendo dos serviços em execução, você pode encontrar neste livro alguns truques para "atacá-los".\
_Obs: às vezes o subdomínio está hospedado dentro de um IP que não é controlado pelo cliente, então não está no escopo, tenha cuidado._

## IPs

Nas etapas iniciais, você pode ter **encontrado algumas faixas de IP, domínios e subdomínios**.\
É hora de **recolher todos os IPs dessas faixas** e dos **domínios/subdomínios (consultas DNS).**

Usando serviços das seguintes **APIs gratuitas**, você também pode encontrar **IPs anteriores usados por domínios e subdomínios**. Esses IPs ainda podem ser de propriedade do cliente (e podem permitir que você encontre [**burlas ao CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

* [**https://securitytrails.com/**](https://securitytrails.com/)

Você também pode verificar os domínios que apontam para um endereço IP específico usando a ferramenta [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Procurando por vulnerabilidades**

**Varredure todas as portas dos IPs que não pertencem a CDNs** (pois provavelmente não encontrará nada interessante lá). Nos serviços em execução descobertos, você pode ser **capaz de encontrar vulnerabilidades**.

**Encontre um** [**guia**](../pentesting-network/) **sobre como escanear hosts.**

## Caça a servidores web

> Encontramos todas as empresas e seus ativos e conhecemos as faixas de IP, domínios e subdomínios dentro do escopo. É hora de procurar por servidores web.

Nas etapas anteriores, você provavelmente já realizou alguma **recon dos IPs e domínios descobertos**, então você pode ter **encontrado todos os possíveis servidores web**. No entanto, se não tivermos, vamos ver agora alguns **truques rápidos para procurar servidores web** dentro do escopo.

Por favor, note que isso será **orientado para a descoberta de aplicativos da web**, então você deve **realizar a vulnerabilidade** e a **varredura de portas** também (**se permitido** pelo escopo).

Um **método rápido** para descobrir **portas abertas** relacionadas a **servidores web** usando [**masscan pode ser encontrado aqui**](../pentesting-network/#http-port-discovery).\
Outra ferramenta amigável para procurar servidores web é [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) e [**httpx**](https://github.com/projectdiscovery/httpx). Basta passar uma lista de domínios e ele tentará se conectar à porta 80 (http) e 443 (https). Além disso, você pode indicar para tentar outras portas:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Capturas de tela**

Agora que você descobriu **todos os servidores web** presentes no escopo (entre os **IPs** da empresa e todos os **domínios** e **subdomínios**), provavelmente **não sabe por onde começar**. Então, vamos simplificar e começar apenas tirando capturas de tela de todos eles. Apenas **dando uma olhada** na **página principal**, você pode encontrar **endpoints estranhos** que são mais **propensos** a serem **vulneráveis**.

Para realizar a ideia proposta, você pode usar [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/) ou [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Além disso, você poderia então usar [**eyeballer**](https://github.com/BishopFox/eyeballer) para percorrer todas as **capturas de tela** e dizer o que provavelmente contém vulnerabilidades e o que não.

## Ativos de Nuvem Pública

Para encontrar possíveis ativos de nuvem pertencentes a uma empresa, você deve **começar com uma lista de palavras-chave que identifiquem essa empresa**. Por exemplo, para uma empresa de criptomoedas, você pode usar palavras como: `"cripto", "carteira", "dao", "<nome_do_domínio>", <"nomes_de_subdomínio">`.

Você também precisará de listas de palavras comuns usadas em buckets:

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Em seguida, com essas palavras, você deve gerar **permutações** (verifique o [**Segundo Round de Brute-Force DNS**](./#second-dns-bruteforce-round) para mais informações).

Com as listas de palavras resultantes, você pode usar ferramentas como [**cloud\_enum**](https://github.com/initstring/cloud\_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **ou** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Lembre-se de que ao procurar Ativos de Nuvem, você deve **procurar mais do que apenas buckets na AWS**.

### **Procurando por vulnerabilidades**

Se você encontrar coisas como **buckets abertos ou funções de nuvem expostas**, você deve **acessá-los** e tentar ver o que eles oferecem e se você pode abusar deles.

## E-mails

Com os **domínios** e **subdomínios** dentro do escopo, você basicamente tem tudo o que **precisa para começar a procurar e-mails**. Estes são os **APIs** e **ferramentas** que funcionaram melhor para mim para encontrar e-mails de uma empresa:

* [**theHarvester**](https://github.com/laramies/theHarvester) - com APIs
* API do [**https://hunter.io/**](https://hunter.io/) (versão gratuita)
* API do [**https://app.snov.io/**](https://app.snov.io/) (versão gratuita)
* API do [**https://minelead.io/**](https://minelead.io/) (versão gratuita)

### **Procurando por vulnerabilidades**

Os e-mails serão úteis mais tarde para **bruteforce em logins web e serviços de autenticação** (como SSH). Além disso, eles são necessários para **phishings**. Além disso, esses APIs lhe darão ainda mais **informações sobre a pessoa** por trás do e-mail, o que é útil para a campanha de phishing.

## Vazamentos de Credenciais

Com os **domínios**, **subdomínios** e **e-mails**, você pode começar a procurar credenciais vazadas no passado pertencentes a esses e-mails:

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **Procurando por vulnerabilidades**

Se você encontrar credenciais vazadas **válidas**, esta é uma vitória muito fácil.

## Vazamentos de Segredos

Vazamentos de credenciais estão relacionados a hacks de empresas onde **informações sensíveis foram vazadas e vendidas**. No entanto, as empresas podem ser afetadas por **outros vazamentos** cujas informações não estão nesses bancos de dados:

### Vazamentos do Github

Credenciais e APIs podem ser vazados nos **repositórios públicos** da **empresa** ou dos **usuários** que trabalham para essa empresa do github.\
Você pode usar a **ferramenta** [**Leakos**](https://github.com/carlospolop/Leakos) para **baixar** todos os **repositórios públicos** de uma **organização** e de seus **desenvolvedores** e executar [**gitleaks**](https://github.com/zricethezav/gitleaks) automaticamente sobre eles.

**Leakos** também pode ser usado para executar **gitleaks** em todos os **textos** fornecidos **URLs passadas** para ele, pois às vezes **páginas da web também contêm segredos**.

#### Dorks do Github

Verifique também esta **página** para possíveis **dorks do github** que você também poderia pesquisar na organização que está atacando:

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Vazamentos de Pastes

Às vezes, atacantes ou apenas trabalhadores irão **publicar conteúdo da empresa em um site de paste**. Isso pode ou não conter **informações sensíveis**, mas é muito interessante procurar por isso.\
Você pode usar a ferramenta [**Pastos**](https://github.com/carlospolop/Pastos) para pesquisar em mais de 80 sites de paste ao mesmo tempo.

### Dorks do Google

Os dorks antigos, mas valiosos do Google, são sempre úteis para encontrar **informações expostas que não deveriam estar lá**. O único problema é que o [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) contém vários **milhares** de consultas possíveis que você não pode executar manualmente. Portanto, você pode escolher suas 10 favoritas ou usar uma **ferramenta como** [**Gorks**](https://github.com/carlospolop/Gorks) **para executá-las todas**.

_Obs: As ferramentas que esperam executar todo o banco de dados usando o navegador regular do Google nunca terminarão, pois o Google bloqueará você muito em breve._

### **Procurando por vulnerabilidades**

Se você encontrar credenciais ou tokens de API vazados **válidos**, esta é uma vitória muito fácil.

## Vulnerabilidades de Código Público

Se você descobrir que a empresa tem **código aberto**, você pode **analisá-lo** e procurar **vulnerabilidades** nele.

**Dependendo da linguagem**, existem diferentes **ferramentas** que você pode usar:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

Também existem serviços gratuitos que permitem que você **escaneie repositórios públicos**, como:

* [**Snyk**](https://app.snyk.io/)
## [**Metodologia de Pentesting Web**](../../network-services-pentesting/pentesting-web/)

A **maioria das vulnerabilidades** encontradas por caçadores de bugs reside dentro de **aplicações web**, então neste ponto eu gostaria de falar sobre uma **metodologia de teste de aplicação web**, e você pode [**encontrar essa informação aqui**](../../network-services-pentesting/pentesting-web/).

Também quero fazer uma menção especial à seção [**Ferramentas de Scanner Automático Web de Código Aberto**](../../network-services-pentesting/pentesting-web/#automatic-scanners), pois, embora você não deva esperar que elas encontrem vulnerabilidades muito sensíveis, elas são úteis para implementá-las em **fluxos de trabalho para obter algumas informações web iniciais.**

## Recapitulação

> Parabéns! Neste ponto, você já realizou **toda a enumeração básica**. Sim, é básica porque muitas outras enumerações podem ser feitas (veremos mais truques depois).

Então você já:

1. Encontrou todas as **empresas** dentro do escopo
2. Encontrou todos os **ativos** pertencentes às empresas (e realizou uma varredura de vulnerabilidades se estiver no escopo)
3. Encontrou todos os **domínios** pertencentes às empresas
4. Encontrou todos os **subdomínios** dos domínios (algum subdomínio para assumir?)
5. Encontrou todos os **IPs** (de e **não de CDNs**) dentro do escopo.
6. Encontrou todos os **servidores web** e tirou um **screenshot** deles (algo estranho que valha uma investigação mais aprofundada?)
7. Encontrou todos os **ativos potenciais de nuvem pública** pertencentes à empresa.
8. **E-mails**, **vazamentos de credenciais** e **vazamentos de segredos** que poderiam lhe dar uma **grande vitória muito facilmente**.
9. **Pentesting em todos os sites que você encontrou**

## **Ferramentas Automáticas de Reconhecimento Completo**

Existem várias ferramentas por aí que executarão parte das ações propostas contra um determinado escopo.

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Um pouco antigo e não atualizado

## **Referências**

* Todos os cursos gratuitos de [**@Jhaddix**](https://twitter.com/Jhaddix) como [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Se você está interessado em uma **carreira de hacking** e hackear o inhackeável - **estamos contratando!** (_fluência em polonês escrita e falada necessária_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
