# Brute Force - CheatSheet

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e automatizar facilmente fluxos de trabalho com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Credenciais Padrão

**Pesquise no Google** por credenciais padrão da tecnologia que está sendo usada, ou **experimente estes links**:

* [**https://github.com/ihebski/DefaultCreds-cheat-sheet**](https://github.com/ihebski/DefaultCreds-cheat-sheet)
* [**http://www.phenoelit.org/dpl/dpl.html**](http://www.phenoelit.org/dpl/dpl.html)
* [**http://www.vulnerabilityassessment.co.uk/passwordsC.htm**](http://www.vulnerabilityassessment.co.uk/passwordsC.htm)
* [**https://192-168-1-1ip.mobi/default-router-passwords-list/**](https://192-168-1-1ip.mobi/default-router-passwords-list/)
* [**https://datarecovery.com/rd/default-passwords/**](https://datarecovery.com/rd/default-passwords/)
* [**https://bizuns.com/default-passwords-list**](https://bizuns.com/default-passwords-list)
* [**https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv**](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://www.cirt.net/passwords**](https://www.cirt.net/passwords)
* [**http://www.passwordsdatabase.com/**](http://www.passwordsdatabase.com)
* [**https://many-passwords.github.io/**](https://many-passwords.github.io)
* [**https://theinfocentric.com/**](https://theinfocentric.com/)

## **Crie seus próprios Dicionários**

Encontre o máximo de informações sobre o alvo que puder e gere um dicionário personalizado. Ferramentas que podem ajudar:

### Crunch
```bash
crunch 4 6 0123456789ABCDEF -o crunch1.txt #From length 4 to 6 using that alphabet
crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha # Only length 4 using charset mixalpha (inside file charset.lst)

@ Lower case alpha characters
, Upper case alpha characters
% Numeric characters
^ Special characters including spac
crunch 6 8 -t ,@@^^%%
```
### Cewl

Cewl is a tool used for generating custom wordlists by scraping websites or documents. It is particularly useful for password cracking through brute force attacks. Cewl works by analyzing the target website or document and extracting relevant words and phrases. These words and phrases are then combined to create a wordlist that can be used in password cracking attempts.

To use Cewl, you need to provide it with a target URL or a document. Cewl will then crawl the target and extract words based on various criteria such as word length, frequency, and relevance. The extracted words are then processed to remove duplicates and irrelevant terms. Finally, Cewl generates a wordlist that can be used in password cracking tools like John the Ripper or Hashcat.

Cewl is a powerful tool for generating custom wordlists that are tailored to the target. By using Cewl, hackers can increase their chances of success in brute force attacks by using wordlists that are more likely to contain the target's password. However, it is important to note that using Cewl for malicious purposes is illegal and unethical. Cewl should only be used for legitimate purposes such as penetration testing or password recovery.
```bash
cewl example.com -m 5 -w words.txt
```
### [CUPP](https://github.com/Mebus/cupp)

Gere senhas com base no seu conhecimento sobre a vítima (nomes, datas...)
```
python3 cupp.py -h
```
### [Wister](https://github.com/cycurity/wister)

Uma ferramenta geradora de listas de palavras, que permite fornecer um conjunto de palavras, dando-lhe a possibilidade de criar várias variações a partir das palavras fornecidas, criando uma lista de palavras única e ideal para uso em relação a um alvo específico.
```bash
python3 wister.py -w jane doe 2022 summer madrid 1998 -c 1 2 3 4 5 -o wordlist.lst

__          _______  _____ _______ ______ _____
\ \        / /_   _|/ ____|__   __|  ____|  __ \
\ \  /\  / /  | | | (___    | |  | |__  | |__) |
\ \/  \/ /   | |  \___ \   | |  |  __| |  _  /
\  /\  /   _| |_ ____) |  | |  | |____| | \ \
\/  \/   |_____|_____/   |_|  |______|_|  \_\

Version 1.0.3                    Cycurity

Generating wordlist...
[########################################] 100%
Generated 67885 lines.

Finished in 0.920s.
```
### [pydictor](https://github.com/LandGrey/pydictor)

### Listas de palavras

* [**https://github.com/danielmiessler/SecLists**](https://github.com/danielmiessler/SecLists)
* [**https://github.com/Dormidera/WordList-Compendium**](https://github.com/Dormidera/WordList-Compendium)
* [**https://github.com/kaonashi-passwords/Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi)
* [**https://github.com/google/fuzzing/tree/master/dictionaries**](https://github.com/google/fuzzing/tree/master/dictionaries)
* [**https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm**](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
* [**https://weakpass.com/wordlist/**](https://weakpass.com/wordlist/)
* [**https://wordlists.assetnote.io/**](https://wordlists.assetnote.io/)
* [**https://github.com/fssecur3/fuzzlists**](https://github.com/fssecur3/fuzzlists)
* [**https://hashkiller.io/listmanager**](https://hashkiller.io/listmanager)
* [**https://github.com/Karanxa/Bug-Bounty-Wordlists**](https://github.com/Karanxa/Bug-Bounty-Wordlists)

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com facilidade, utilizando as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Serviços

Ordenados alfabeticamente pelo nome do serviço.

### AFP
```bash
nmap -p 548 --script afp-brute <IP>
msf> use auxiliary/scanner/afp/afp_login
msf> set BLANK_PASSWORDS true
msf> set USER_AS_PASS true
msf> set PASS_FILE <PATH_PASSWDS>
msf> set USER_FILE <PATH_USERS>
msf> run
```
### AJP

O Protocolo de Janela de Ativação (AJP) é um protocolo de comunicação usado para transferir solicitações entre um servidor web e um servidor de aplicativos. Ele é frequentemente usado em ambientes Java para permitir a comunicação entre um servidor web, como o Apache HTTP Server, e um servidor de aplicativos, como o Apache Tomcat.

O AJP é um protocolo binário que permite uma comunicação eficiente e de baixa latência entre os servidores. Ele suporta várias operações, como a transferência de solicitações HTTP, a obtenção de informações sobre a sessão do usuário e a execução de solicitações assíncronas.

No entanto, o AJP também pode ser explorado por hackers para realizar ataques de força bruta. Um ataque de força bruta envolve tentar todas as combinações possíveis de senhas até encontrar a correta. Os hackers podem usar ferramentas automatizadas para enviar solicitações AJP com várias combinações de senhas em uma tentativa de adivinhar a senha correta e obter acesso não autorizado ao servidor.

Para proteger contra ataques de força bruta no AJP, é importante implementar medidas de segurança adequadas, como a configuração de senhas fortes e a limitação do número de tentativas de login. Além disso, é recomendável monitorar os logs do servidor em busca de atividades suspeitas e manter o software do servidor atualizado com as últimas correções de segurança.

Em resumo, o AJP é um protocolo de comunicação usado para transferir solicitações entre servidores web e servidores de aplicativos. Embora seja eficiente, também pode ser explorado por hackers para realizar ataques de força bruta. Portanto, é essencial implementar medidas de segurança adequadas para proteger contra esses ataques.
```bash
nmap --script ajp-brute -p 8009 <IP>
```
# Brute Force

O ataque de força bruta é uma técnica comum usada pelos hackers para obter acesso não autorizado a sistemas ou contas. Nesse tipo de ataque, o invasor tenta todas as combinações possíveis de senhas até encontrar a correta. 

Embora seja uma abordagem simples, o ataque de força bruta pode ser eficaz se a senha for fraca ou se o sistema não tiver medidas de segurança adequadas para detectar e bloquear tentativas repetidas de login. 

Existem várias ferramentas disponíveis para realizar ataques de força bruta, como Hydra e Medusa. Essas ferramentas automatizam o processo de tentativa de login, permitindo que o invasor teste várias combinações de senhas em um curto período de tempo. 

Para proteger-se contra ataques de força bruta, é importante usar senhas fortes e complexas, que sejam difíceis de adivinhar. Além disso, é recomendável implementar medidas de segurança, como bloqueio de contas após um número específico de tentativas de login malsucedidas.
```bash
nmap --script cassandra-brute -p 9160 <IP>
```
# Brute Force

## Introdução

O ataque de força bruta é uma técnica comum usada por hackers para obter acesso não autorizado a sistemas ou contas. Nesse tipo de ataque, o hacker tenta adivinhar a senha correta testando várias combinações possíveis até encontrar a senha correta.

## Ataque de Força Bruta no CouchDB

O CouchDB é um banco de dados NoSQL que armazena dados em formato JSON. Ele possui uma API RESTful que permite a interação com o banco de dados. O CouchDB também possui um mecanismo de autenticação embutido que protege o acesso aos dados.

No entanto, se as configurações de segurança não forem adequadamente implementadas, o CouchDB pode ser vulnerável a ataques de força bruta. Um hacker pode usar ferramentas automatizadas para tentar várias combinações de nomes de usuário e senhas até encontrar as credenciais corretas.

## Mitigação

Para proteger o CouchDB contra ataques de força bruta, é importante seguir as práticas recomendadas de segurança:

1. Use senhas fortes: Certifique-se de que as senhas usadas para autenticação no CouchDB sejam complexas e difíceis de adivinhar. Use uma combinação de letras maiúsculas e minúsculas, números e caracteres especiais.

2. Limite as tentativas de login: Configure o CouchDB para bloquear temporariamente um endereço IP após um número específico de tentativas de login malsucedidas. Isso ajudará a evitar ataques de força bruta automatizados.

3. Implemente autenticação de dois fatores: Adicione uma camada adicional de segurança exigindo que os usuários forneçam um segundo fator de autenticação, como um código enviado por SMS, além da senha.

4. Mantenha o CouchDB atualizado: Certifique-se de que você esteja usando a versão mais recente do CouchDB, pois as atualizações geralmente incluem correções de segurança.

5. Monitore os logs de acesso: Fique atento a atividades suspeitas nos logs de acesso do CouchDB. Isso pode ajudar a identificar tentativas de força bruta em andamento.

## Conclusão

Embora o CouchDB seja um banco de dados poderoso e flexível, é importante implementar medidas de segurança adequadas para proteger contra ataques de força bruta. Ao seguir as práticas recomendadas mencionadas acima, você pode fortalecer a segurança do CouchDB e reduzir o risco de acesso não autorizado.
```bash
msf> use auxiliary/scanner/couchdb/couchdb_login
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 5984 http-get /
```
### Registro do Docker

O Registro do Docker é um serviço que permite armazenar e distribuir imagens Docker. Ele é usado para compartilhar imagens entre desenvolvedores e implantar aplicativos em ambientes de produção. O Registro do Docker pode ser executado em um servidor local ou em um serviço em nuvem, como o Docker Hub.

#### Ataques de Força Bruta

Um ataque de força bruta é uma técnica usada para descobrir senhas ou chaves de acesso a um sistema. No contexto do Registro do Docker, um ataque de força bruta pode ser usado para tentar adivinhar a senha de um usuário ou a chave de acesso de um repositório.

Existem várias ferramentas disponíveis para realizar ataques de força bruta contra o Registro do Docker. Essas ferramentas automatizam o processo de tentar várias combinações de senhas ou chaves de acesso até encontrar a correta.

Para proteger o Registro do Docker contra ataques de força bruta, é importante seguir as melhores práticas de segurança, como:

- Usar senhas fortes e complexas.
- Implementar políticas de bloqueio de conta após várias tentativas de login malsucedidas.
- Monitorar e registrar atividades suspeitas no Registro do Docker.
- Atualizar regularmente o Registro do Docker com as versões mais recentes para corrigir quaisquer vulnerabilidades conhecidas.

Além disso, é recomendável usar autenticação de dois fatores (2FA) para adicionar uma camada extra de segurança ao acesso ao Registro do Docker. Isso exige que os usuários forneçam um segundo fator de autenticação, como um código gerado por um aplicativo de autenticação, além de suas credenciais de login padrão.

Ao implementar essas medidas de segurança, é possível reduzir significativamente o risco de um ataque de força bruta bem-sucedido contra o Registro do Docker.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt  -P /usr/share/brutex/wordlists/password.lst 10.10.10.10 -s 5000 https-get /v2/
```
# Elasticsearch

O Elasticsearch é um mecanismo de busca e análise distribuído, que é amplamente utilizado para pesquisar, analisar e visualizar grandes volumes de dados em tempo real. Ele é construído sobre o Apache Lucene e fornece uma interface RESTful para interagir com os dados.

## Força Bruta

A força bruta é uma técnica comum usada para quebrar senhas ou descobrir informações confidenciais, tentando todas as combinações possíveis até encontrar a correta. No contexto do Elasticsearch, a força bruta pode ser usada para tentar adivinhar credenciais de autenticação e obter acesso não autorizado ao sistema.

Existem várias ferramentas disponíveis para realizar ataques de força bruta no Elasticsearch, como o Hydra e o Burp Suite. Essas ferramentas automatizam o processo de tentativa de várias combinações de nomes de usuário e senhas em uma velocidade muito alta.

Para proteger seu cluster Elasticsearch contra ataques de força bruta, é importante implementar medidas de segurança adequadas, como:

- Usar senhas fortes e complexas para as contas de usuário.
- Implementar bloqueio de conta após um número específico de tentativas de login malsucedidas.
- Configurar firewalls e listas de permissões para restringir o acesso ao cluster.
- Monitorar e registrar atividades suspeitas no cluster.

Ao implementar essas medidas de segurança, você pode reduzir significativamente o risco de um ataque bem-sucedido de força bruta no seu cluster Elasticsearch.
```
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst localhost -s 9200 http-get /
```
### FTP

O FTP (File Transfer Protocol) é um protocolo amplamente utilizado para transferir arquivos entre um cliente e um servidor em uma rede. É comumente usado para fazer upload e download de arquivos de um servidor remoto para um computador local e vice-versa.

#### Ataques de Força Bruta

Um ataque de força bruta é uma técnica usada para descobrir senhas ou chaves criptográficas adivinhando todas as combinações possíveis até encontrar a correta. No contexto do FTP, um ataque de força bruta envolve tentar todas as combinações possíveis de nomes de usuário e senhas para obter acesso não autorizado a uma conta FTP.

Existem várias ferramentas disponíveis para realizar ataques de força bruta no FTP, como o Hydra e o Medusa. Essas ferramentas automatizam o processo de tentar várias combinações de nomes de usuário e senhas em uma velocidade muito alta.

Para proteger uma conta FTP contra ataques de força bruta, é importante usar senhas fortes e implementar medidas de segurança, como bloqueio de IP após várias tentativas falhas de login. Além disso, é recomendável usar autenticação de dois fatores para adicionar uma camada extra de segurança.

#### Dicionários de Senhas

Um dicionário de senhas é uma lista de palavras ou combinações de caracteres que são usadas em ataques de força bruta para tentar adivinhar senhas. Esses dicionários podem ser criados manualmente ou baixados de fontes disponíveis publicamente.

Os dicionários de senhas geralmente contêm palavras comuns, nomes de usuários, senhas padrão e outras combinações que são frequentemente usadas como senhas. Os atacantes usam esses dicionários para automatizar o processo de adivinhar senhas em ataques de força bruta.

É importante usar senhas fortes e exclusivas que não estejam presentes em dicionários de senhas conhecidos para evitar ataques de força bruta bem-sucedidos. Além disso, é recomendável implementar medidas de segurança, como bloqueio de IP após várias tentativas falhas de login, para dificultar ainda mais os ataques de força bruta.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ftp
ncrack -p 21 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ftp
```
### Brute Force Genérico HTTP

#### [**WFuzz**](../pentesting-web/web-tool-wfuzz.md)

### Autenticação Básica HTTP
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst sizzle.htb.local http-get /certsrv/
# Use https-get mode for https
medusa -h <IP> -u <username> -P  <passwords.txt> -M  http -m DIR:/path/to/auth -T 10
```
### HTTP - Postar Formulário

O método de brute force pode ser usado para atacar formulários de login em sites que utilizam o protocolo HTTP. Nesse tipo de ataque, o hacker tenta todas as combinações possíveis de nomes de usuário e senhas até encontrar a combinação correta que permite o acesso ao sistema.

Existem várias ferramentas disponíveis que podem automatizar esse processo, como o Hydra e o Medusa. Essas ferramentas permitem que o hacker especifique uma lista de nomes de usuário e senhas, e então as testem automaticamente no formulário de login.

Para realizar um ataque de brute force em um formulário de login HTTP, o hacker precisa capturar a requisição HTTP POST que é enviada quando o formulário é submetido. Essa requisição contém os parâmetros do formulário, como o nome de usuário e a senha.

O hacker pode então usar uma ferramenta como o Burp Suite para modificar a requisição POST e substituir os valores dos parâmetros do formulário pelos valores que ele deseja testar. Em seguida, ele pode enviar a requisição modificada repetidamente, testando diferentes combinações de nomes de usuário e senhas.

É importante ressaltar que o uso de brute force para atacar sistemas é ilegal e antiético, a menos que seja realizado com permissão explícita do proprietário do sistema como parte de um teste de penetração autorizado.
```bash
hydra -L /usr/share/brutex/wordlists/simple-users.txt -P /usr/share/brutex/wordlists/password.lst domain.htb  http-post-form "/path/index.php:name=^USER^&password=^PASS^&enter=Sign+in:Login name or password is incorrect" -V
# Use https-post-form mode for https
```
Para http**s**, você precisa mudar de "http-post-form" para "**https-post-form**"

### **HTTP - CMS --** (W)ordpress, (J)oomla ou (D)rupal ou (M)oodle
```bash
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
```
O IMAP (Internet Message Access Protocol) é um protocolo de email que permite aos usuários acessar e gerenciar suas mensagens de email em um servidor remoto. O IMAP é amplamente utilizado por clientes de email para sincronizar caixas de correio e manter uma cópia das mensagens no servidor. Isso permite que os usuários acessem suas mensagens de email de diferentes dispositivos e locais. O IMAP também suporta recursos avançados, como pastas, pesquisa de mensagens e marcação de mensagens como lidas ou não lidas.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> imap -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 993 -f <IP> imap -V
nmap -sV --script imap-brute -p <PORT> <IP>
```
IRC (Internet Relay Chat) é um protocolo de comunicação utilizado para trocar mensagens em tempo real através da internet. É amplamente utilizado para comunicação em grupo, discussões e suporte técnico. O IRC é baseado em canais, onde os usuários podem se juntar e participar de conversas. O protocolo IRC permite que os usuários se conectem a servidores IRC e interajam com outros usuários por meio de comandos específicos. O IRC também suporta recursos como bate-papo privado, transferência de arquivos e compartilhamento de informações.
```bash
nmap -sV --script irc-brute,irc-sasl-brute --script-args userdb=/path/users.txt,passdb=/path/pass.txt -p <PORT> <IP>
```
### ISCSI

O iSCSI (Internet Small Computer System Interface) é um protocolo de rede que permite a comunicação entre dispositivos de armazenamento de dados, como discos rígidos, e servidores através de uma rede IP. Ele é amplamente utilizado para acessar e gerenciar dispositivos de armazenamento remotos.

O iSCSI utiliza o método de autenticação CHAP (Challenge-Handshake Authentication Protocol) para garantir a segurança das comunicações entre o servidor e o dispositivo de armazenamento. Além disso, ele suporta a criptografia de dados para proteger as informações transmitidas.

Uma das técnicas de ataque comumente usadas contra o iSCSI é o brute force, que envolve a tentativa de adivinhar a senha de acesso ao dispositivo de armazenamento através de uma série de tentativas consecutivas. Os hackers podem usar ferramentas automatizadas para realizar ataques de brute force, explorando a fraqueza de senhas fracas ou previsíveis.

Para proteger-se contra ataques de brute force, é importante utilizar senhas fortes e complexas, que sejam difíceis de adivinhar. Além disso, é recomendado implementar medidas de segurança adicionais, como bloqueio de contas após um número específico de tentativas falhas e monitoramento de atividades suspeitas.

Em resumo, o iSCSI é um protocolo de rede utilizado para acessar dispositivos de armazenamento remotos. No entanto, é importante estar ciente dos riscos de segurança associados a ele e tomar medidas adequadas para proteger os dados armazenados.
```bash
nmap -sV --script iscsi-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 3260 <IP>
```
### JWT

O JSON Web Token (JWT) é um método de autenticação amplamente utilizado na web. Ele permite que os usuários se autentiquem e acessem recursos protegidos por meio de um token seguro. Um JWT consiste em três partes: o cabeçalho, a carga útil e a assinatura.

#### Cabeçalho

O cabeçalho de um JWT contém informações sobre o tipo de token e o algoritmo de assinatura usado. Geralmente, o tipo de token é definido como "JWT" e o algoritmo de assinatura pode ser HMAC, RSA ou ECDSA.

#### Carga útil

A carga útil de um JWT contém as informações que são transmitidas entre as partes envolvidas. Essas informações podem incluir dados do usuário, como o ID do usuário, o nome e as permissões.

#### Assinatura

A assinatura de um JWT é usada para verificar a integridade do token e garantir que ele não tenha sido alterado durante a transmissão. A assinatura é gerada usando uma chave secreta conhecida apenas pelo emissor e pelo receptor do token.

#### Ataques de força bruta

Os ataques de força bruta são uma técnica comum usada para quebrar senhas ou chaves criptográficas. Nesse tipo de ataque, o invasor tenta todas as combinações possíveis até encontrar a senha ou chave correta.

#### Protegendo contra ataques de força bruta

Existem várias maneiras de proteger um sistema contra ataques de força bruta. Alguns métodos eficazes incluem:

- Implementar bloqueio de conta após várias tentativas falhas de login.
- Usar senhas fortes e complexas.
- Implementar um mecanismo de autenticação de dois fatores.
- Usar algoritmos de hash fortes para armazenar senhas.

#### Conclusão

O JWT é uma forma popular de autenticação na web, mas é importante protegê-lo contra ataques de força bruta. Implementar medidas de segurança adequadas pode ajudar a garantir a integridade e a segurança do sistema.
```bash
#hashcat
hashcat -m 16500 -a 0 jwt.txt .\wordlists\rockyou.txt

#https://github.com/Sjord/jwtcrack
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#John
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256

#https://github.com/ticarpi/jwt_tool
python3 jwt_tool.py -d wordlists.txt <JWT token>

#https://github.com/brendan-rius/c-jwt-cracker
./jwtcrack eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc 1234567890 8

#https://github.com/mazen160/jwt-pwn
python3 jwt-cracker.py -jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc -w wordlist.txt

#https://github.com/lmammino/jwt-cracker
jwt-cracker "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ" "abcdefghijklmnopqrstuwxyz" 6
```
LDAP (Lightweight Directory Access Protocol) é um protocolo de aplicação usado para acessar e gerenciar serviços de diretório. Ele fornece uma maneira padronizada de consultar, adicionar, modificar e excluir informações em um diretório. O LDAP é amplamente utilizado para autenticação e autorização em sistemas de rede, como servidores de e-mail e sistemas de gerenciamento de identidade.
```bash
nmap --script ldap-brute -p 389 <IP>
```
### MQTT

MQTT (Message Queuing Telemetry Transport) é um protocolo de mensagens leve e de baixa largura de banda, projetado para comunicação entre dispositivos conectados à Internet das Coisas (IoT). Ele é amplamente utilizado para troca de mensagens entre dispositivos e servidores em redes de IoT.

O MQTT utiliza um modelo de publicação/assinatura, onde os dispositivos podem publicar mensagens em tópicos específicos e outros dispositivos podem se inscrever nesses tópicos para receber as mensagens. Isso permite uma comunicação eficiente e escalável entre os dispositivos.

No entanto, como qualquer protocolo de comunicação, o MQTT também pode ser alvo de ataques. Um dos ataques mais comuns é o ataque de força bruta, onde um invasor tenta adivinhar as credenciais de autenticação de um dispositivo MQTT. Isso pode ser feito tentando várias combinações de nomes de usuário e senhas até encontrar a combinação correta.

Para proteger um sistema MQTT contra ataques de força bruta, é importante implementar medidas de segurança adequadas, como:

- Usar senhas fortes e complexas para autenticação.
- Limitar o número de tentativas de login.
- Implementar bloqueio de conta após várias tentativas de login malsucedidas.
- Utilizar criptografia para proteger as comunicações MQTT.

Além disso, é importante manter o software MQTT atualizado com as últimas correções de segurança e seguir as melhores práticas de segurança recomendadas pelo fornecedor do software.

Ao implementar essas medidas de segurança, é possível reduzir significativamente o risco de um ataque de força bruta bem-sucedido em um sistema MQTT.
```
ncrack mqtt://127.0.0.1 --user test –P /root/Desktop/pass.txt -v
```
### Mongo

Mongo é um banco de dados NoSQL amplamente utilizado que armazena dados em formato de documento. Ele é conhecido por sua escalabilidade e flexibilidade, tornando-o uma escolha popular para aplicativos modernos. No entanto, como qualquer sistema, o Mongo também pode ser alvo de ataques de hackers.

Uma técnica comum usada para atacar o Mongo é a força bruta. A força bruta envolve tentar todas as combinações possíveis de senhas até encontrar a correta. Isso é feito usando programas automatizados que testam várias senhas em uma taxa muito alta.

Para proteger seu banco de dados Mongo contra ataques de força bruta, é importante seguir algumas práticas recomendadas. Em primeiro lugar, certifique-se de usar senhas fortes e complexas que sejam difíceis de adivinhar. Além disso, é recomendável implementar medidas de segurança adicionais, como limitar o número de tentativas de login permitidas e bloquear endereços IP suspeitos.

Outra maneira de proteger seu banco de dados Mongo é mantendo-o atualizado com as últimas correções de segurança. Os desenvolvedores do Mongo lançam regularmente atualizações que corrigem vulnerabilidades conhecidas. Certifique-se de aplicar essas atualizações assim que estiverem disponíveis.

Além disso, é importante monitorar o tráfego de rede em busca de atividades suspeitas. Isso pode ajudar a identificar tentativas de força bruta em tempo real e tomar medidas para mitigar o ataque.

Ao implementar essas práticas recomendadas, você pode fortalecer a segurança do seu banco de dados Mongo e reduzir o risco de ataques de força bruta bem-sucedidos.
```bash
nmap -sV --script mongodb-brute -n -p 27017 <IP>
use auxiliary/scanner/mongodb/mongodb_login
```
### MySQL

O MySQL é um sistema de gerenciamento de banco de dados relacional de código aberto amplamente utilizado. Ele fornece uma maneira eficiente de armazenar, organizar e recuperar dados. O MySQL usa a linguagem SQL (Structured Query Language) para consultar e manipular dados em um banco de dados.

#### Ataques de força bruta contra o MySQL

Um ataque de força bruta é uma técnica usada para descobrir senhas ou chaves de criptografia, tentando todas as combinações possíveis até encontrar a correta. No contexto do MySQL, um ataque de força bruta pode ser usado para tentar adivinhar a senha de um usuário com acesso ao banco de dados.

Existem várias ferramentas disponíveis para realizar ataques de força bruta contra o MySQL. Essas ferramentas automatizam o processo de tentar várias combinações de senhas em um curto período de tempo. Os atacantes podem usar dicionários de senhas comuns ou gerar senhas aleatórias para tentar adivinhar a senha correta.

Para proteger o MySQL contra ataques de força bruta, é importante implementar medidas de segurança, como:

- Usar senhas fortes e complexas para os usuários do MySQL.
- Limitar o número de tentativas de login permitidas antes de bloquear temporariamente o acesso.
- Implementar autenticação de dois fatores para adicionar uma camada extra de segurança.
- Monitorar e registrar atividades suspeitas de login.

Além disso, é recomendável manter o MySQL atualizado com as últimas correções de segurança e seguir as práticas recomendadas de segurança.
```bash
# hydra
hydra -L usernames.txt -P pass.txt <IP> mysql

# msfconsole
msf> use auxiliary/scanner/mysql/mysql_login; set VERBOSE false

# medusa
medusa -h <IP/Host> -u <username> -P <password_list> <-f | to stop medusa on first success attempt> -t <threads> -M mysql
```
# Brute Force

## Introdução

O ataque de força bruta é uma técnica comum usada por hackers para obter acesso não autorizado a sistemas protegidos por senha. Neste capítulo, discutiremos o uso de força bruta no contexto do OracleSQL.

## O que é OracleSQL?

OracleSQL é uma linguagem de consulta estruturada usada para gerenciar e manipular bancos de dados Oracle. É amplamente utilizado em aplicativos empresariais e é conhecido por sua segurança robusta.

## Ataque de Força Bruta no OracleSQL

Um ataque de força bruta no OracleSQL envolve tentar todas as combinações possíveis de senhas até encontrar a correta. Isso é feito usando um programa automatizado que gera e testa senhas em alta velocidade.

## Ferramentas de Força Bruta

Existem várias ferramentas disponíveis para realizar ataques de força bruta no OracleSQL. Alguns exemplos populares incluem Hydra, Medusa e Ncrack. Essas ferramentas são altamente configuráveis e podem ser ajustadas para atender às necessidades específicas do atacante.

## Mitigação de Ataques de Força Bruta

Existem várias medidas que podem ser tomadas para mitigar ataques de força bruta no OracleSQL. Alguns exemplos incluem:

- Implementar políticas de senha fortes que exijam senhas complexas e de comprimento adequado.
- Bloquear contas após um número específico de tentativas de login malsucedidas.
- Implementar autenticação multifator para adicionar uma camada extra de segurança.

## Conclusão

O ataque de força bruta no OracleSQL é uma técnica perigosa usada por hackers para obter acesso não autorizado a sistemas protegidos por senha. É importante implementar medidas de segurança adequadas para mitigar esse tipo de ataque e proteger os sistemas contra invasões indesejadas.
```bash
patator oracle_login sid=<SID> host=<IP> user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017

./odat.py passwordguesser -s $SERVER -d $SID
./odat.py passwordguesser -s $MYSERVER -p $PORT --accounts-file accounts_multiple.txt

#msf1
msf> use admin/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORT 1521
msf> set SID <SID>

#msf2, this option uses nmap and it fails sometimes for some reason
msf> use scanner/oracle/oracle_login
msf> set RHOSTS <IP>
msf> set RPORTS 1521
msf> set SID <SID>

#for some reason nmap fails sometimes when executing this script
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=<SID> <IP>
```
Para usar **oracle\_login** com **patator**, você precisa **instalar**:
```bash
pip3 install cx_Oracle --upgrade
```
[Força bruta de hash OracleSQL offline](../network-services-pentesting/1521-1522-1529-pentesting-oracle-listener/remote-stealth-pass-brute-force.md#outer-perimeter-remote-stealth-pass-brute-force) (**versões 11.1.0.6, 11.1.0.7, 11.2.0.1, 11.2.0.2,** e **11.2.0.3**):
```bash
nmap -p1521 --script oracle-brute-stealth --script-args oracle-brute-stealth.sid=DB11g -n 10.11.21.30
```
POP (Post Office Protocol) is a protocol used for retrieving email messages from a mail server. It is commonly used by email clients to download emails from a remote server to a local device. 

Brute forcing POP accounts involves systematically trying different combinations of usernames and passwords until a valid login is found. This method can be effective if the target has weak or easily guessable credentials. 

To perform a brute force attack on a POP account, you can use tools like Hydra or Medusa. These tools allow you to automate the process of trying different username and password combinations. 

It is important to note that brute forcing is an aggressive and potentially illegal hacking technique. It should only be used with proper authorization and for legitimate purposes, such as penetration testing.
```bash
hydra -l USERNAME -P /path/to/passwords.txt -f <IP> pop3 -V
hydra -S -v -l USERNAME -P /path/to/passwords.txt -s 995 -f <IP> pop3 -V
```
# Brute Force

O ataque de força bruta é uma técnica comum usada para obter acesso não autorizado a sistemas ou contas. Nesse tipo de ataque, o invasor tenta adivinhar a senha correta testando várias combinações possíveis até encontrar a senha correta.

## Ataque de Força Bruta no PostgreSQL

O PostgreSQL é um sistema de gerenciamento de banco de dados relacional popular que também pode ser alvo de ataques de força bruta. Os invasores podem tentar adivinhar as senhas das contas de usuário do PostgreSQL para obter acesso não autorizado ao banco de dados.

Existem várias ferramentas disponíveis que podem ser usadas para realizar ataques de força bruta no PostgreSQL. Essas ferramentas automatizam o processo de tentar várias combinações de senhas em uma velocidade muito alta, aumentando assim as chances de sucesso do ataque.

## Protegendo contra ataques de força bruta

Existem várias medidas que podem ser tomadas para proteger o PostgreSQL contra ataques de força bruta:

- Use senhas fortes: Certifique-se de que as senhas das contas de usuário do PostgreSQL sejam fortes e não fáceis de adivinhar. Isso inclui o uso de uma combinação de letras maiúsculas e minúsculas, números e caracteres especiais.

- Limite as tentativas de login: Configure o PostgreSQL para limitar o número de tentativas de login permitidas em um determinado período de tempo. Isso pode ajudar a evitar ataques de força bruta, pois os invasores terão um número limitado de tentativas para adivinhar a senha correta.

- Monitore os logs de autenticação: Monitore regularmente os logs de autenticação do PostgreSQL em busca de atividades suspeitas. Isso pode ajudar a identificar tentativas de ataques de força bruta e tomar medidas preventivas.

- Atualize regularmente: Mantenha o PostgreSQL atualizado com as últimas correções de segurança. Isso pode ajudar a proteger contra vulnerabilidades conhecidas que podem ser exploradas em ataques de força bruta.

- Use autenticação de dois fatores: Considere a implementação da autenticação de dois fatores para adicionar uma camada extra de segurança ao PostgreSQL. Isso exigirá que os usuários forneçam uma segunda forma de autenticação, além da senha, para acessar o banco de dados.

Ao implementar essas medidas de segurança, você pode ajudar a proteger o PostgreSQL contra ataques de força bruta e manter seus dados seguros.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> postgres
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M postgres
ncrack –v –U /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP>:5432
patator pgsql_login host=<IP> user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt
use auxiliary/scanner/postgres/postgres_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>
```
### PPTP

Você pode baixar o pacote `.deb` para instalar em [https://http.kali.org/pool/main/t/thc-pptp-bruter/](https://http.kali.org/pool/main/t/thc-pptp-bruter/)
```bash
sudo dpkg -i thc-pptp-bruter*.deb #Install the package
cat rockyou.txt | thc-pptp-bruter –u <Username> <IP>
```
### RDP

O Protocolo de Desktop Remoto (RDP) é um protocolo de rede desenvolvido pela Microsoft que permite a um usuário controlar e acessar remotamente um computador através de uma conexão de rede. O RDP é comumente usado para fins de suporte técnico, administração remota e acesso a desktops virtuais.

#### Ataques de Força Bruta

Um ataque de força bruta é uma técnica usada para descobrir senhas ou chaves criptográficas através da tentativa de todas as combinações possíveis até encontrar a correta. No contexto do RDP, um ataque de força bruta envolve tentar todas as combinações possíveis de nomes de usuário e senhas para acessar um sistema RDP.

Existem várias ferramentas disponíveis para realizar ataques de força bruta no RDP, como o Hydra e o Medusa. Essas ferramentas automatizam o processo de tentativa de login com várias combinações de credenciais.

Para proteger um sistema RDP contra ataques de força bruta, é importante implementar medidas de segurança, como:

- Usar senhas fortes e complexas que sejam difíceis de adivinhar.
- Implementar bloqueio de conta após um número específico de tentativas de login malsucedidas.
- Configurar um firewall para bloquear endereços IP suspeitos ou fontes de tráfego malicioso.
- Atualizar regularmente o sistema operacional e o software RDP para corrigir quaisquer vulnerabilidades conhecidas.

Além disso, é recomendável monitorar os logs de eventos do sistema para detectar atividades suspeitas ou tentativas de login malsucedidas.
```bash
ncrack -vv --user <User> -P pwds.txt rdp://<IP>
hydra -V -f -L <userslist> -P <passwlist> rdp://<IP>
```
# Brute Force

O brute force é uma técnica de ataque que envolve tentar todas as combinações possíveis de senhas até encontrar a correta. É uma abordagem direta e demorada, mas pode ser eficaz se a senha for fraca ou se o número de combinações possíveis for pequeno.

No contexto do Redis, o brute force pode ser usado para tentar adivinhar a senha de acesso a um servidor Redis protegido por autenticação. O Redis é um banco de dados em memória que é frequentemente usado como cache ou armazenamento de dados temporários. Se um invasor conseguir acessar um servidor Redis, ele pode obter informações confidenciais ou até mesmo comprometer outros sistemas conectados a ele.

Existem várias ferramentas disponíveis para realizar ataques de brute force no Redis. Essas ferramentas automatizam o processo de tentar várias combinações de senhas em um curto período de tempo. Além disso, existem listas de senhas comuns disponíveis na internet, que podem ser usadas como ponto de partida para um ataque de brute force.

Para proteger um servidor Redis contra ataques de brute force, é importante seguir boas práticas de segurança, como:

- Usar senhas fortes e complexas, que sejam difíceis de adivinhar.
- Limitar o número de tentativas de login, bloqueando temporariamente o IP após um número específico de falhas.
- Monitorar os logs de acesso para detectar atividades suspeitas.
- Manter o servidor Redis atualizado com as últimas correções de segurança.

Ao implementar essas medidas de segurança, é possível reduzir significativamente o risco de um ataque de brute force bem-sucedido no Redis.
```bash
msf> use auxiliary/scanner/redis/redis_login
nmap --script redis-brute -p 6379 <IP>
hydra –P /path/pass.txt redis://<IP>:<PORT> # 6379 is the default
```
### Rexec

O Rexec é um protocolo de rede que permite a execução remota de comandos em um servidor. É comumente usado para fins administrativos, permitindo que os administradores executem comandos em servidores remotos sem precisar fazer login diretamente no servidor.

No entanto, o Rexec também pode ser explorado por hackers para realizar ataques de força bruta. Um ataque de força bruta é quando um hacker tenta adivinhar a senha correta de um usuário, testando várias combinações possíveis até encontrar a senha correta.

Para realizar um ataque de força bruta no Rexec, um hacker usaria um programa automatizado que tenta várias combinações de senhas em rápida sucessão. O objetivo é encontrar a senha correta e obter acesso não autorizado ao servidor.

Existem várias ferramentas disponíveis para realizar ataques de força bruta no Rexec, como o Hydra e o Medusa. Essas ferramentas são capazes de testar milhares de combinações de senhas por segundo, tornando o processo de adivinhar a senha muito mais rápido.

Para se proteger contra ataques de força bruta no Rexec, é importante usar senhas fortes e complexas. Além disso, é recomendável implementar medidas de segurança adicionais, como bloqueio de IP após várias tentativas de login malsucedidas e monitoramento de atividades suspeitas no servidor.
```bash
hydra -l <username> -P <password_file> rexec://<Victim-IP> -v -V
```
### Rlogin

O Rlogin é um protocolo de rede que permite a um usuário se conectar a um servidor remoto usando autenticação baseada em senha. Ele é amplamente utilizado para acesso remoto a sistemas Unix-like.

#### Técnica de Força Bruta

A técnica de força bruta é um método utilizado para descobrir senhas através de tentativas repetidas de todas as combinações possíveis. No contexto do Rlogin, um atacante pode usar a técnica de força bruta para tentar adivinhar a senha de um usuário remoto.

#### Ferramentas e Recursos

Existem várias ferramentas e recursos disponíveis para realizar ataques de força bruta no Rlogin. Alguns exemplos incluem:

- Hydra: uma ferramenta de força bruta que suporta vários protocolos, incluindo Rlogin.
- Medusa: uma ferramenta de força bruta rápida e modular que também suporta o protocolo Rlogin.
- Dicionários de senhas: listas de palavras comumente usadas como senhas, que podem ser usadas em ataques de força bruta.

#### Mitigação

Para mitigar ataques de força bruta no Rlogin, é recomendado implementar as seguintes medidas de segurança:

- Use senhas fortes: escolha senhas complexas e exclusivas que sejam difíceis de adivinhar.
- Limite as tentativas de login: configure o servidor Rlogin para bloquear temporariamente contas após um número específico de tentativas de login malsucedidas.
- Implemente autenticação de dois fatores: adicione uma camada extra de segurança exigindo um segundo fator de autenticação, como um código enviado por SMS ou um token de segurança.

Lembre-se de que a realização de ataques de força bruta sem permissão é ilegal e pode resultar em consequências legais graves.
```bash
hydra -l <username> -P <password_file> rlogin://<Victim-IP> -v -V
```
### Rsh

O Rsh (Remote Shell) é um protocolo de rede que permite a execução remota de comandos em um sistema Unix ou Linux. Ele é usado para estabelecer uma conexão entre um cliente e um servidor, permitindo que o cliente execute comandos no servidor como se estivesse localmente conectado a ele.

O Rsh é um protocolo simples que não oferece autenticação ou criptografia, o que o torna vulnerável a ataques de brute force. Um ataque de brute force no Rsh envolve tentar todas as combinações possíveis de senhas até encontrar a correta. Isso é feito usando um programa automatizado que tenta repetidamente diferentes senhas até obter acesso ao sistema.

Para proteger um sistema contra ataques de brute force no Rsh, é importante implementar medidas de segurança, como a configuração de senhas fortes e a restrição de acesso ao serviço Rsh apenas a partir de hosts confiáveis. Além disso, é recomendável desativar completamente o serviço Rsh, se possível, e usar alternativas mais seguras, como o SSH (Secure Shell).
```bash
hydra -L <Username_list> rsh://<Victim_IP> -v -V
```
[http://pentestmonkey.net/tools/misc/rsh-grind](http://pentestmonkey.net/tools/misc/rsh-grind)

### Rsync

Rsync é uma ferramenta de sincronização de arquivos amplamente utilizada que permite transferir e sincronizar dados entre sistemas remotos. É especialmente útil para fazer backup de arquivos e espelhar diretórios entre servidores.

No contexto de testes de penetração, o Rsync pode ser explorado para realizar ataques de força bruta. Um ataque de força bruta envolve tentar todas as combinações possíveis de senhas até encontrar a correta. Isso é feito enviando solicitações de autenticação ao servidor Rsync com diferentes combinações de nome de usuário e senha.

O Rsync também pode ser usado para explorar senhas fracas ou previsíveis. Ao usar uma lista de senhas comuns ou uma lista de palavras-chave relacionadas ao alvo, é possível automatizar o processo de força bruta e tentar várias combinações rapidamente.

É importante ressaltar que a realização de ataques de força bruta sem permissão é ilegal e antiética. Essas técnicas devem ser usadas apenas para fins legítimos, como testes de segurança em sistemas autorizados.
```bash
nmap -sV --script rsync-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 873 <IP>
```
### RTSP

O Protocolo de Transmissão em Tempo Real (RTSP, do inglês Real-Time Streaming Protocol) é um protocolo de rede utilizado para controlar a transmissão contínua de dados em tempo real, como áudio e vídeo, através de redes IP. Ele permite que os clientes controlem a reprodução de mídia em servidores de streaming.

O RTSP é frequentemente utilizado em aplicativos de vigilância por vídeo, onde é necessário transmitir e controlar o fluxo de vídeo em tempo real. Ele também pode ser usado em outras aplicações que envolvam transmissão de mídia, como videoconferências e transmissões ao vivo.

O protocolo RTSP utiliza o método de autenticação de força bruta para tentar adivinhar as credenciais de acesso a um servidor de streaming. Esse método envolve a tentativa de várias combinações de nomes de usuário e senhas até encontrar a combinação correta que permite o acesso ao servidor.

A autenticação de força bruta é uma técnica comum usada por hackers para obter acesso não autorizado a sistemas protegidos. É importante que os administradores de sistemas implementem medidas de segurança adequadas, como senhas fortes e bloqueio de contas após várias tentativas de login malsucedidas, para evitar ataques de força bruta.
```bash
hydra -l root -P passwords.txt <IP> rtsp
```
O SNMP (Simple Network Management Protocol) é um protocolo amplamente utilizado para gerenciamento de redes. Ele permite que os administradores monitorem e gerenciem dispositivos de rede, como roteadores, switches e servidores. O SNMP opera usando uma estrutura cliente-servidor, onde os dispositivos de rede atuam como agentes SNMP e os sistemas de gerenciamento de rede atuam como gerentes SNMP.

O SNMP usa uma variedade de comandos para coletar informações dos dispositivos de rede, como consultas GET e SET. No entanto, uma técnica comum usada por hackers é a força bruta, que envolve tentar todas as combinações possíveis de senhas até encontrar a correta. Isso é feito usando ferramentas automatizadas, como o Hydra, que podem testar várias senhas em um curto período de tempo.

Para proteger os dispositivos SNMP contra ataques de força bruta, é importante seguir boas práticas de segurança, como usar senhas fortes e complexas, limitar o acesso ao protocolo SNMP apenas a sistemas autorizados e monitorar regularmente os logs de atividades para detectar atividades suspeitas. Além disso, é recomendável implementar mecanismos de bloqueio temporário após várias tentativas de login malsucedidas para evitar ataques de força bruta.
```bash
msf> use auxiliary/scanner/snmp/snmp_login
nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt <IP>
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com snmp
```
### SMB

O SMB (Server Message Block) é um protocolo de compartilhamento de arquivos e impressoras usado em redes locais do Windows. Ele permite que os usuários acessem e compartilhem recursos, como arquivos e impressoras, em uma rede. O SMB também é usado para comunicação entre computadores em uma rede, permitindo a transferência de arquivos e o acesso a serviços de rede.

#### Ataques de Força Bruta

Um ataque de força bruta é uma técnica usada para descobrir senhas ou chaves criptográficas adivinhando todas as combinações possíveis até encontrar a correta. No contexto do SMB, um ataque de força bruta pode ser usado para tentar adivinhar a senha de uma conta de usuário ou de um recurso compartilhado.

Existem várias ferramentas disponíveis para realizar ataques de força bruta no SMB, como o Hydra e o Medusa. Essas ferramentas automatizam o processo de tentar várias combinações de senhas em uma velocidade muito alta, permitindo que um atacante tente milhões de senhas em pouco tempo.

Para proteger-se contra ataques de força bruta no SMB, é importante usar senhas fortes e complexas, que sejam difíceis de adivinhar. Além disso, é recomendável implementar medidas de segurança adicionais, como bloqueio de contas após várias tentativas de login malsucedidas e monitoramento de atividades suspeitas na rede.
```bash
nmap --script smb-brute -p 445 <IP>
hydra -l Administrator -P words.txt 192.168.1.12 smb -t 1
```
### SMTP

O Simple Mail Transfer Protocol (SMTP) é um protocolo de comunicação utilizado para enviar e receber e-mails. Ele é amplamente utilizado na comunicação de servidores de e-mail e permite que os usuários enviem mensagens de e-mail para destinatários em diferentes domínios.

O SMTP é baseado em texto e opera na porta 25. Ele segue um conjunto de regras e comandos para transferir mensagens de e-mail entre servidores. O processo de envio de e-mails usando o SMTP envolve a autenticação do remetente, a identificação do destinatário e a transferência da mensagem.

No entanto, o SMTP também pode ser explorado por hackers para realizar ataques de força bruta. Um ataque de força bruta no SMTP envolve tentar todas as combinações possíveis de senhas para obter acesso não autorizado a uma conta de e-mail. Os hackers podem usar ferramentas automatizadas para realizar esses ataques, tentando várias senhas em rápida sucessão até encontrar a correta.

Para se proteger contra ataques de força bruta no SMTP, é importante implementar medidas de segurança, como a configuração de senhas fortes e a limitação do número de tentativas de login. Além disso, é recomendável monitorar os logs do servidor de e-mail em busca de atividades suspeitas e manter o software do servidor de e-mail atualizado com as últimas correções de segurança.
```bash
hydra -l <username> -P /path/to/passwords.txt <IP> smtp -V
hydra -l <username> -P /path/to/passwords.txt -s 587 <IP> -S -v -V #Port 587 for SMTP with SSL
```
SOCKS (Socket Secure) is a protocol that allows for the secure transmission of network packets between a client and a server through a proxy server. It operates at the transport layer of the OSI model and can be used for various purposes, including bypassing network restrictions and anonymizing internet traffic.

### Brute Force Attack

A brute force attack is a method used by hackers to gain unauthorized access to a system or account by systematically trying all possible combinations of passwords or encryption keys until the correct one is found. This method relies on the assumption that the password or key is weak and can be easily guessed through trial and error.

Brute force attacks can be time-consuming and resource-intensive, especially when dealing with complex passwords or encryption algorithms. However, they can be effective against systems with weak security measures in place.

To protect against brute force attacks, it is important to use strong and unique passwords, implement account lockout policies, and employ additional security measures such as two-factor authentication.
```bash
nmap  -vvv -sCV --script socks-brute --script-args userdb=users.txt,passdb=/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt,unpwndb.timelimit=30m -p 1080 <IP>
```
### SSH

SSH (Secure Shell) é um protocolo de rede criptografado que permite a comunicação segura entre dois sistemas. É comumente usado para acessar e controlar servidores remotos de forma segura. O SSH utiliza criptografia assimétrica para autenticar e estabelecer uma conexão segura, garantindo a confidencialidade e integridade dos dados transmitidos.

#### Força Bruta SSH

A força bruta SSH é uma técnica usada para descobrir senhas de acesso a servidores SSH por meio de tentativas repetidas de combinações de senhas. Essa técnica envolve o uso de programas automatizados que tentam todas as combinações possíveis de senhas até encontrar a correta.

Embora a força bruta SSH possa ser eficaz contra senhas fracas, ela é geralmente ineficiente contra senhas fortes e sistemas que implementam medidas de segurança adicionais, como bloqueio de IP após várias tentativas falhas. Portanto, é importante usar senhas fortes e implementar medidas de segurança adequadas para proteger os servidores SSH contra ataques de força bruta.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> ssh
ncrack -p 22 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M ssh
patator ssh_login host=<ip> port=22 user=root 0=/path/passwords.txt password=FILE0 -x ignore:mesg='Authentication failed'
```
#### Chaves SSH fracas / PRNG previsível do Debian

Alguns sistemas possuem falhas conhecidas na semente aleatória usada para gerar material criptográfico. Isso pode resultar em um espaço de chaves dramaticamente reduzido, que pode ser quebrado por ferramentas como [snowdroppe/ssh-keybrute](https://github.com/snowdroppe/ssh-keybrute). Conjuntos pré-gerados de chaves fracas também estão disponíveis, como [g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh).

### SQL Server
```bash
#Use the NetBIOS name of the machine as domain
crackmapexec mssql <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt <IP> mssql
medusa -h <IP> –U /root/Desktop/user.txt –P /root/Desktop/pass.txt –M mssql
nmap -p 1433 --script ms-sql-brute --script-args mssql.domain=DOMAIN,userdb=customuser.txt,passdb=custompass.txt,ms-sql-brute.brute-windows-accounts <host> #Use domain if needed. Be careful with the number of passwords in the list, this could block accounts
msf> use auxiliary/scanner/mssql/mssql_login #Be careful, you can block accounts. If you have a domain set it and use USE_WINDOWS_ATHENT
```
Telnet is a protocol used for remote access to computers over a network. It allows users to log in to a remote system and execute commands as if they were directly connected to it. Telnet is often used for administrative purposes, such as configuring network devices or troubleshooting issues.

Telnet is a clear-text protocol, which means that all communication between the client and the server is sent in plain text. This lack of encryption makes Telnet vulnerable to eavesdropping and interception of sensitive information, such as usernames and passwords.

Brute-forcing Telnet involves systematically trying all possible combinations of usernames and passwords until the correct credentials are found. This technique is often used by attackers to gain unauthorized access to systems with weak or default credentials.

To perform a Telnet brute-force attack, an attacker typically uses automated tools that can rapidly try different username and password combinations. These tools can leverage dictionaries of commonly used passwords or generate random combinations to increase the chances of success.

To protect against Telnet brute-force attacks, it is important to use strong, unique passwords and disable any default or weak credentials. Additionally, implementing account lockout policies and monitoring for suspicious login attempts can help detect and mitigate brute-force attacks.
```bash
hydra -l root -P passwords.txt [-t 32] <IP> telnet
ncrack -p 23 --user root -P passwords.txt <IP> [-T 5]
medusa -u root -P 500-worst-passwords.txt -h <IP> -M telnet
```
### VNC

O VNC (Virtual Network Computing) é um protocolo de compartilhamento de desktop remoto que permite que um usuário controle e visualize a interface gráfica de um computador remotamente. O VNC é amplamente utilizado para fins de suporte técnico, administração de sistemas e acesso remoto a computadores.

#### Ataques de Força Bruta contra o VNC

Um ataque de força bruta é uma técnica usada para descobrir senhas ou chaves criptográficas adivinhando repetidamente combinações possíveis até encontrar a correta. No contexto do VNC, um ataque de força bruta envolve a tentativa de adivinhar a senha de acesso ao servidor VNC.

Existem várias ferramentas disponíveis para realizar ataques de força bruta contra o VNC, como o Hydra e o Medusa. Essas ferramentas automatizam o processo de tentativa de várias combinações de senhas em uma velocidade muito alta.

Para proteger um servidor VNC contra ataques de força bruta, é importante seguir as melhores práticas de segurança, como:

- Usar senhas fortes e complexas que sejam difíceis de adivinhar.
- Implementar bloqueio de conta após um número específico de tentativas de login malsucedidas.
- Utilizar uma VPN ou firewall para restringir o acesso ao servidor VNC apenas a endereços IP confiáveis.
- Manter o software VNC atualizado com as últimas correções de segurança.

Ao realizar testes de penetração em um servidor VNC, é importante obter permissão explícita do proprietário do sistema antes de realizar qualquer atividade de hacking. O uso não autorizado de técnicas de força bruta pode ser ilegal e sujeito a penalidades legais.
```bash
hydra -L /root/Desktop/user.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc
medusa -h <IP> –u root -P /root/Desktop/pass.txt –M vnc
ncrack -V --user root -P /root/Desktop/pass.txt <IP>:>POR>T
patator vnc_login host=<IP> password=FILE0 0=/root/Desktop/pass.txt –t 1 –x retry:fgep!='Authentication failure' --max-retries 0 –x quit:code=0
use auxiliary/scanner/vnc/vnc_login
nmap -sV --script pgsql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt -p 5432 <IP>

#Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS <ip>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.lst
```
### Winrm

O Winrm (Windows Remote Management) é um protocolo de gerenciamento remoto desenvolvido pela Microsoft para facilitar a administração de sistemas Windows. Ele permite que os administradores executem comandos e gerenciem recursos em computadores remotos.

#### Ataques de força bruta contra o Winrm

Um ataque de força bruta contra o Winrm envolve tentar adivinhar a senha de uma conta de usuário através de tentativas repetidas. Os atacantes usam programas automatizados para testar várias combinações de senhas até encontrar a correta.

Existem várias ferramentas disponíveis para realizar ataques de força bruta contra o Winrm, como o Hydra e o Medusa. Essas ferramentas permitem que os atacantes testem uma lista de senhas comuns ou personalizadas em uma tentativa de obter acesso não autorizado a um sistema remoto.

Para proteger-se contra ataques de força bruta no Winrm, é importante implementar medidas de segurança, como o uso de senhas fortes e a configuração de bloqueio de conta após um número específico de tentativas falhas. Além disso, é recomendado monitorar os logs de eventos do Winrm para detectar atividades suspeitas e implementar autenticação de dois fatores sempre que possível.
```bash
crackmapexec winrm <IP> -d <Domain Name> -u usernames.txt -p passwords.txt
```
<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e automatizar facilmente fluxos de trabalho com as ferramentas comunitárias mais avançadas do mundo.
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Local

### Bancos de dados de quebra de senha online

* [~~http://hashtoolkit.com/reverse-hash?~~](http://hashtoolkit.com/reverse-hash?) (MD5 e SHA1)
* [https://shuck.sh/get-shucking.php](https://shuck.sh/get-shucking.php) (MSCHAPv2/PPTP-VPN/NetNTLMv1 com/sem ESS/SSP e com qualquer valor de desafio)
* [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com) (Hashes, capturas WPA2 e arquivos MSOffice, ZIP, PDF...)
* [https://crackstation.net/](https://crackstation.net) (Hashes)
* [https://md5decrypt.net/](https://md5decrypt.net) (MD5)
* [https://gpuhash.me/](https://gpuhash.me) (Hashes e hashes de arquivos)
* [https://hashes.org/search.php](https://hashes.org/search.php) (Hashes)
* [https://www.cmd5.org/](https://www.cmd5.org) (Hashes)
* [https://hashkiller.co.uk/Cracker](https://hashkiller.co.uk/Cracker) (MD5, NTLM, SHA1, MySQL5, SHA256, SHA512)
* [https://www.md5online.org/md5-decrypt.html](https://www.md5online.org/md5-decrypt.html) (MD5)
* [http://reverse-hash-lookup.online-domain-tools.com/](http://reverse-hash-lookup.online-domain-tools.com)

Verifique isso antes de tentar forçar a quebra de um Hash.

### ZIP
```bash
#sudo apt-get install fcrackzip
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
```

```bash
zip2john file.zip > zip.john
john zip.john
```

```bash
#$zip2$*0*3*0*a56cb83812be3981ce2a83c581e4bc4f*4d7b*24*9af41ff662c29dfff13229eefad9a9043df07f2550b9ad7dfc7601f1a9e789b5ca402468*694b6ebb6067308bedcd*$/zip2$
hashcat.exe -m 13600 -a 0 .\hashzip.txt .\wordlists\rockyou.txt
.\hashcat.exe -m 13600 -i -a 0 .\hashzip.txt #Incremental attack
```
#### Ataque de força bruta com texto conhecido em arquivos zip

Você precisa conhecer o **texto em claro** (ou parte do texto em claro) **de um arquivo contido dentro** do zip criptografado. Você pode verificar **os nomes de arquivos e o tamanho dos arquivos contidos** em um zip criptografado executando: **`7z l encrypted.zip`**\
Baixe o [**bkcrack**](https://github.com/kimci86/bkcrack/releases/tag/v1.4.0) na página de lançamentos.
```bash
# You need to create a zip file containing only the file that is inside the encrypted zip
zip plaintext.zip plaintext.file

./bkcrack -C <encrypted.zip> -c <plaintext.file> -P <plaintext.zip> -p <plaintext.file>
# Now wait, this should print a key such as 7b549874 ebc25ec5 7e465e18
# With that key you can create a new zip file with the content of encrypted.zip
# but with a different pass that you set (so you can decrypt it)
./bkcrack -C <encrypted.zip> -k 7b549874 ebc25ec5 7e465e18 -U unlocked.zip new_pwd
unzip unlocked.zip #User new_pwd as password
```
### 7z

O 7z é um formato de arquivo compactado que oferece alta taxa de compressão. Ele é amplamente utilizado para compactar e descompactar arquivos em sistemas operacionais Windows. O 7z utiliza o algoritmo de compressão LZMA para reduzir o tamanho dos arquivos, tornando-os mais fáceis de armazenar e transferir.

#### Ataques de força bruta contra senhas 7z

Os arquivos 7z podem ser protegidos por senhas para garantir a segurança dos dados. No entanto, em alguns casos, é necessário realizar ataques de força bruta para recuperar senhas esquecidas ou perdidas.

Um ataque de força bruta contra senhas 7z envolve tentar todas as combinações possíveis de caracteres até encontrar a senha correta. Isso pode ser feito usando ferramentas de cracking de senhas, como o John the Ripper ou o Hashcat.

É importante ressaltar que realizar um ataque de força bruta contra senhas é uma atividade ilegal, a menos que você tenha permissão explícita do proprietário do arquivo. Sempre obtenha autorização antes de realizar qualquer tipo de teste de segurança ou hacking.
```bash
cat /usr/share/wordlists/rockyou.txt | 7za t backup.7z
```

```bash
#Download and install requirements for 7z2john
wget https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/7z2john.pl
apt-get install libcompress-raw-lzma-perl
./7z2john.pl file.7z > 7zhash.john
```
# Força Bruta

A técnica de força bruta é um método comum usado por hackers para obter acesso não autorizado a sistemas ou contas protegidas por senha. Nesse método, o hacker tenta todas as combinações possíveis de senhas até encontrar a correta.

## Como funciona a força bruta?

A força bruta envolve a tentativa de todas as combinações possíveis de senhas até que a senha correta seja encontrada. Isso é feito usando programas automatizados que testam várias combinações em uma taxa muito alta.

## Ferramentas de força bruta

Existem várias ferramentas disponíveis para realizar ataques de força bruta. Algumas das ferramentas populares incluem Hydra, Medusa e John the Ripper. Essas ferramentas são altamente configuráveis e podem ser usadas para atacar uma variedade de sistemas e serviços.

## Mitigação de ataques de força bruta

Existem várias medidas que podem ser tomadas para mitigar ataques de força bruta. Alguns exemplos incluem:

- Implementar políticas de senha fortes que exijam senhas complexas e de comprimento adequado.
- Bloquear temporariamente contas após um número específico de tentativas de login malsucedidas.
- Implementar autenticação de dois fatores para adicionar uma camada extra de segurança.
- Monitorar e registrar atividades suspeitas de login para identificar padrões de ataque.

## Conclusão

A técnica de força bruta é uma abordagem comum usada por hackers para obter acesso não autorizado a sistemas protegidos por senha. É importante implementar medidas de segurança adequadas para mitigar esses ataques e proteger as contas e sistemas contra invasões.
```bash
apt-get install pdfcrack
pdfcrack encrypted.pdf -w /usr/share/wordlists/rockyou.txt
#pdf2john didn't work well, john didn't know which hash type was
# To permanently decrypt the pdf
sudo apt-get install qpdf
qpdf --password=<PASSWORD> --decrypt encrypted.pdf plaintext.pdf
```
### Senha do Proprietário do PDF

Para quebrar uma senha do proprietário de um PDF, verifique isso: [https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/](https://blog.didierstevens.com/2022/06/27/quickpost-cracking-pdf-owner-passwords/)

### JWT
```bash
git clone https://github.com/Sjord/jwtcrack.git
cd jwtcrack

#Bruteforce using crackjwt.py
python crackjwt.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc /usr/share/wordlists/rockyou.txt

#Bruteforce using john
python jwt2john.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1widXNlcm5hbWVcIjpcImFkbWluXCIsXCJyb2xlXCI6XCJhZG1pblwifSJ9.8R-KVuXe66y_DXVOVgrEqZEoadjBnpZMNbLGhM8YdAc > jwt.john
john jwt.john #It does not work with Kali-John
```
### Quebra de NTLM

A quebra de NTLM é uma técnica utilizada para descobrir senhas de hashes NTLM. O NTLM é um protocolo de autenticação utilizado em sistemas Windows. Ao obter um hash NTLM, é possível realizar a quebra utilizando força bruta.

A quebra de NTLM por força bruta envolve a tentativa de todas as combinações possíveis de senhas até encontrar a correspondente ao hash NTLM. Existem várias ferramentas disponíveis para realizar esse tipo de ataque, como o John the Ripper e o Hashcat.

É importante ressaltar que a quebra de NTLM por força bruta pode ser um processo demorado, especialmente se a senha for complexa. Portanto, é recomendado utilizar senhas fortes e implementar medidas de segurança adicionais para proteger os hashes NTLM.
```bash
Format:USUARIO:ID:HASH_LM:HASH_NT:::
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT file_NTLM.hashes
hashcat -a 0 -m 1000 --username file_NTLM.hashes /usr/share/wordlists/rockyou.txt --potfile-path salida_NT.pot
```
### Keepass

O Keepass é um gerenciador de senhas de código aberto que permite armazenar e gerenciar com segurança todas as suas senhas em um único local. Ele usa criptografia forte para proteger suas informações confidenciais e oferece recursos como a geração automática de senhas fortes e a capacidade de organizar suas senhas em categorias.

Uma das técnicas comuns de ataque contra senhas é a força bruta, onde um invasor tenta adivinhar a senha correta testando todas as combinações possíveis. No entanto, o Keepass é projetado para resistir a ataques de força bruta, implementando medidas de segurança, como o bloqueio da conta após um número específico de tentativas falhas de login.

Embora o Keepass seja uma ferramenta segura para armazenar suas senhas, é importante lembrar de escolher uma senha mestra forte e única para proteger seu banco de dados do Keepass. Além disso, é recomendável manter o Keepass atualizado com as versões mais recentes, pois isso garante que quaisquer vulnerabilidades conhecidas sejam corrigidas.

Em resumo, o Keepass é uma solução confiável para gerenciar suas senhas com segurança, protegendo-as contra ataques de força bruta e fornecendo uma maneira conveniente de acessar suas senhas quando necessário.
```bash
sudo apt-get install -y kpcli #Install keepass tools like keepass2john
keepass2john file.kdbx > hash #The keepass is only using password
keepass2john -k <file-password> file.kdbx > hash # The keepass is also using a file as a needed credential
#The keepass can use a password and/or a file as credentials, if it is using both you need to provide them to keepass2john
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
### Keberoasting

Keberoasting é uma técnica de ataque que visa explorar senhas fracas em contas de serviço do Active Directory (AD). Essa técnica se baseia na fraqueza do protocolo Kerberos, que permite que um atacante extraia hashes de senha de contas de serviço sem a necessidade de autenticação.

O processo de Keberoasting envolve a identificação de contas de serviço no AD que possuem a propriedade "ServicePrincipalName" definida. Essas contas de serviço geralmente são usadas para executar serviços em segundo plano, como serviços de banco de dados, servidores web e outros aplicativos.

Uma vez identificadas as contas de serviço, o atacante pode solicitar um ticket de serviço para a conta desejada. O ticket de serviço contém o hash da senha da conta de serviço, que pode ser extraído pelo atacante.

Com o hash da senha em mãos, o atacante pode usar técnicas de força bruta ou ataques de dicionário para tentar quebrar a senha e obter acesso à conta de serviço. Essa técnica é eficaz porque muitas vezes as senhas de contas de serviço são fracas e fáceis de adivinhar.

Para se proteger contra ataques de Keberoasting, é recomendado que as senhas de contas de serviço sejam fortes e complexas. Além disso, é importante monitorar e auditar regularmente as contas de serviço para detectar atividades suspeitas.
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Imagem do Lucks

#### Método 1

Instale: [https://github.com/glv2/bruteforce-luks](https://github.com/glv2/bruteforce-luks)
```bash
bruteforce-luks -f ./list.txt ./backup.img
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
#### Método 2

Brute force is a common method used in hacking to gain unauthorized access to a system or account. It involves systematically trying all possible combinations of passwords until the correct one is found.

Brute force attacks can be time-consuming and resource-intensive, especially if the password is long and complex. However, they can be effective against weak passwords or poorly implemented security measures.

There are several tools available for conducting brute force attacks, such as Hydra and Medusa. These tools automate the process by attempting multiple login attempts in a short period of time.

To protect against brute force attacks, it is important to use strong, unique passwords and implement account lockout policies. Additionally, rate limiting and CAPTCHA can be used to prevent automated login attempts.

It is also worth noting that brute force attacks can be detected by monitoring for multiple failed login attempts from the same IP address or user account.
```bash
cryptsetup luksDump backup.img #Check that the payload offset is set to 4096
dd if=backup.img of=luckshash bs=512 count=4097 #Payload offset +1
hashcat -m 14600 -a 0 luckshash  wordlists/rockyou.txt
cryptsetup luksOpen backup.img mylucksopen
ls /dev/mapper/ #You should find here the image mylucksopen
mount /dev/mapper/mylucksopen /mnt
```
Outro tutorial de BF Luks: [http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1](http://blog.dclabs.com.br/2020/03/bruteforcing-linux-disk-encription-luks.html?m=1)

### Mysql
```bash
#John hash format
<USERNAME>:$mysqlna$<CHALLENGE>*<RESPONSE>
dbuser:$mysqlna$112233445566778899aabbccddeeff1122334455*73def07da6fba5dcc1b19c918dbd998e0d1f3f9d
```
### Chave privada PGP/GPG

A chave privada PGP/GPG é um componente essencial para a criptografia de dados. Ela é usada para descriptografar mensagens criptografadas com a chave pública correspondente. A chave privada deve ser mantida em sigilo absoluto, pois qualquer pessoa que a possua pode acessar e decifrar as mensagens protegidas por ela.

A perda ou comprometimento da chave privada pode resultar na exposição de informações sensíveis e na violação da privacidade. Portanto, é fundamental proteger adequadamente a chave privada PGP/GPG, armazenando-a em um local seguro e utilizando medidas de segurança adicionais, como senhas fortes e autenticação de dois fatores.

Além disso, é importante fazer backup da chave privada PGP/GPG regularmente, para evitar a perda irreversível de dados. Ao fazer o backup, certifique-se de armazenar a chave em um local seguro e criptografado, de preferência em um dispositivo externo ou em um serviço de armazenamento em nuvem confiável.

Lembre-se de que a chave privada PGP/GPG é uma parte crítica da criptografia de dados e deve ser tratada com extrema cautela. Mantenha-a protegida e segura para garantir a confidencialidade e integridade das suas comunicações.
```bash
gpg2john private_pgp.key #This will generate the hash and save it in a file
john --wordlist=/usr/share/wordlists/rockyou.txt ./hash
```
### Cisco

<figure><img src="../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

### Chave Mestra DPAPI

Use [https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py) e depois john

### Coluna Protegida por Senha no Open Office

Se você tiver um arquivo xlsx com uma coluna protegida por senha, você pode desprotegê-la:

* **Faça o upload para o Google Drive** e a senha será removida automaticamente
* Para **removê-la** **manualmente**:
```bash
unzip file.xlsx
grep -R "sheetProtection" ./*
# Find something like: <sheetProtection algorithmName="SHA-512"
hashValue="hFq32ZstMEekuneGzHEfxeBZh3hnmO9nvv8qVHV8Ux+t+39/22E3pfr8aSuXISfrRV9UVfNEzidgv+Uvf8C5Tg" saltValue="U9oZfaVCkz5jWdhs9AA8nA" spinCount="100000" sheet="1" objects="1" scenarios="1"/>
# Remove that line and rezip the file
zip -r file.xls .
```
### Certificados PFX

Certificados PFX são arquivos que contêm chaves privadas e certificados públicos em um formato específico. Eles são usados para autenticação e criptografia em várias aplicações e serviços. Os certificados PFX são protegidos por uma senha, o que garante a segurança das chaves privadas.

### Ataques de Força Bruta

Um ataque de força bruta é uma técnica usada para quebrar senhas ou chaves criptográficas, tentando todas as combinações possíveis até encontrar a correta. Esse tipo de ataque pode ser usado para tentar quebrar a senha de um certificado PFX.

Existem várias ferramentas disponíveis para realizar ataques de força bruta, como o Hydra e o Medusa. Essas ferramentas automatizam o processo de tentar várias combinações de senhas em um curto período de tempo.

No entanto, é importante ressaltar que ataques de força bruta podem ser demorados e consomem muitos recursos computacionais. Além disso, eles podem ser detectados por sistemas de segurança, como firewalls e sistemas de detecção de intrusão.

Portanto, é recomendado que senhas fortes sejam utilizadas para proteger certificados PFX, a fim de dificultar ou impedir ataques de força bruta bem-sucedidos.
```bash
# From https://github.com/Ridter/p12tool
./p12tool crack -c staff.pfx -f /usr/share/wordlists/rockyou.txt
# From https://github.com/crackpkcs12/crackpkcs12
crackpkcs12 -d /usr/share/wordlists/rockyou.txt ./cert.pfx
```
<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente, utilizando as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Ferramentas

**Exemplos de hash:** [https://openwall.info/wiki/john/sample-hashes](https://openwall.info/wiki/john/sample-hashes)

### Identificador de Hash
```bash
hash-identifier
> <HASH>
```
### Listas de palavras

* **Rockyou**
* [**Probable-Wordlists**](https://github.com/berzerk0/Probable-Wordlists)
* [**Kaonashi**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/wordlists)
* [**Seclists - Passwords**](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

### **Ferramentas de geração de listas de palavras**

* [**kwprocessor**](https://github.com/hashcat/kwprocessor)**:** Gerador avançado de sequências de teclado com caracteres base, mapa de teclas e rotas configuráveis.
```bash
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o D:\Tools\keywalk.txt
```
### Mutação de John

Leia _**/etc/john/john.conf**_ e configure-o.
```bash
john --wordlist=words.txt --rules --stdout > w_mutated.txt
john --wordlist=words.txt --rules=all --stdout > w_mutated.txt #Apply all rules
```
### Hashcat

#### Ataques do Hashcat

* **Ataque de lista de palavras** (`-a 0`) com regras

O **Hashcat** já vem com uma **pasta contendo regras**, mas você pode encontrar [**outras regras interessantes aqui**](https://github.com/kaonashi-passwords/Kaonashi/tree/master/rules).
```
hashcat.exe -a 0 -m 1000 C:\Temp\ntlm.txt .\rockyou.txt -r rules\best64.rule
```
* **Ataque de combinação de listas de palavras**

É possível **combinar 2 listas de palavras em 1** com o hashcat.\
Se a lista 1 contiver a palavra **"hello"** e a segunda contiver 2 linhas com as palavras **"world"** e **"earth"**. As palavras `helloworld` e `helloearth` serão geradas.
```bash
# This will combine 2 wordlists
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt

# Same attack as before but adding chars in the newly generated words
# In the previous example this will generate:
## hello-world!
## hello-earth!
hashcat.exe -a 1 -m 1000 C:\Temp\ntlm.txt .\wordlist1.txt .\wordlist2.txt -j $- -k $!
```
* **Ataque de máscara** (`-a 3`)
```bash
# Mask attack with simple mask
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

hashcat --help #will show the charsets and are as follows
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff

# Mask attack declaring custom charset
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1
## -1 ?d?s defines a custom charset (digits and specials).
## ?u?l?l?l?l?l?l?l?1 is the mask, where "?1" is the custom charset.

# Mask attack with variable password length
## Create a file called masks.hcmask with this content:
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
## Use it to crack the password
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt .\masks.hcmask
```
* Ataque de Wordlist + Máscara (`-a 6`) / Máscara + Wordlist (`-a 7`)
```bash
# Mask numbers will be appended to each word in the wordlist
hashcat.exe -a 6 -m 1000 C:\Temp\ntlm.txt \wordlist.txt ?d?d?d?d

# Mask numbers will be prepended to each word in the wordlist
hashcat.exe -a 7 -m 1000 C:\Temp\ntlm.txt ?d?d?d?d \wordlist.txt
```
#### Modos do Hashcat

Hashcat é uma ferramenta de quebra de senha que suporta vários modos de ataque. Cada modo é projetado para atacar um tipo específico de hash ou algoritmo de criptografia. Os modos do Hashcat incluem:

- **Modo de força bruta**: Este modo tenta todas as combinações possíveis de caracteres até encontrar a senha correta. É o método mais básico e demorado, mas pode ser eficaz para senhas fracas.

- **Modo de dicionário**: Neste modo, o Hashcat usa uma lista de palavras conhecidas (dicionário) para tentar encontrar a senha. É mais rápido do que o modo de força bruta, mas requer um dicionário de alta qualidade.

- **Modo de ataque de regra**: Este modo aplica regras personalizadas às palavras do dicionário para gerar variações e aumentar as chances de encontrar a senha. As regras podem incluir inversão de caracteres, adição de números, substituição de letras, entre outras.

- **Modo de ataque de máscara**: Neste modo, o Hashcat usa uma máscara personalizada para gerar todas as combinações possíveis de caracteres com base em um padrão definido. É útil quando você conhece parte da senha ou o formato em que ela está.

- **Modo de ataque híbrido**: Este modo combina o uso de um dicionário com o modo de ataque de máscara. Ele permite que você especifique uma parte fixa da senha e gere todas as combinações possíveis para a parte variável.

- **Modo de ataque de força bruta combinada**: Neste modo, o Hashcat combina dois ou mais arquivos de hash para realizar um ataque de força bruta em todas as combinações possíveis. É útil quando você tem várias hashes e deseja encontrar uma senha que funcione para todas elas.

- **Modo de ataque de força bruta híbrida**: Este modo combina o uso de um dicionário com o modo de ataque de força bruta. Ele permite que você especifique uma parte fixa da senha e tente todas as combinações possíveis para a parte variável.

- **Modo de ataque de força bruta incremental**: Neste modo, o Hashcat tenta todas as combinações possíveis de caracteres em uma ordem específica. É útil quando você tem uma ideia aproximada da senha, mas não sabe a ordem exata dos caracteres.

Cada modo de ataque tem suas vantagens e desvantagens, e a escolha do modo certo depende do tipo de hash ou algoritmo de criptografia que você está tentando quebrar.
```bash
hashcat --example-hashes | grep -B1 -A2 "NTLM"
```
# Quebrando Hashes do Linux - arquivo /etc/shadow

## Introdução

O arquivo `/etc/shadow` é um arquivo importante no sistema operacional Linux, pois armazena as senhas criptografadas dos usuários. Ao realizar um teste de penetração em um sistema Linux, é comum tentar quebrar essas senhas criptografadas para obter acesso não autorizado.

## Metodologia de Força Bruta

A metodologia de força bruta é uma técnica comum usada para quebrar senhas criptografadas. Consiste em tentar todas as combinações possíveis de caracteres até encontrar a senha correta. Embora seja um método demorado, pode ser eficaz se a senha for fraca ou se o atacante tiver recursos computacionais significativos.

## Ferramentas de Força Bruta

Existem várias ferramentas disponíveis para realizar ataques de força bruta em senhas do Linux. Algumas das ferramentas mais populares incluem:

- **John the Ripper**: uma ferramenta de quebra de senha altamente configurável e amplamente utilizada.
- **Hashcat**: uma ferramenta de quebra de senha de alto desempenho que suporta vários algoritmos de hash.
- **Hydra**: uma ferramenta de força bruta de login em rede que também pode ser usada para quebrar senhas do Linux.

## Considerações de Segurança

É importante lembrar que a quebra de senhas é uma atividade ilegal, a menos que seja realizada com permissão explícita do proprietário do sistema. Além disso, é fundamental usar senhas fortes e criptografia adequada para proteger os sistemas contra ataques de força bruta.

## Conclusão

A quebra de senhas criptografadas do Linux pode ser realizada usando a metodologia de força bruta e várias ferramentas disponíveis. No entanto, é importante lembrar que a segurança dos sistemas depende de senhas fortes e práticas adequadas de segurança.
```
500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
```
# Quebrando Hashes do Windows

## Introdução

Quebrar hashes do Windows é uma técnica comum usada por hackers para obter senhas de contas de usuário em sistemas operacionais Windows. Os hashes são representações criptografadas das senhas armazenadas nos bancos de dados do sistema. Ao quebrar esses hashes, os hackers podem obter acesso não autorizado às contas de usuário.

## Metodologia de Força Bruta

A metodologia de força bruta é uma abordagem comum para quebrar hashes do Windows. Nessa técnica, o hacker tenta todas as combinações possíveis de senhas até encontrar a correspondência correta com o hash. Isso é feito usando programas de cracking de senha que automatizam o processo de tentativa e erro.

## Ferramentas de Quebra de Hashes

Existem várias ferramentas disponíveis para quebrar hashes do Windows. Algumas das mais populares incluem:

- John the Ripper
- Hashcat
- Cain & Abel

Essas ferramentas são capazes de quebrar hashes usando diferentes técnicas, como força bruta, dicionário e ataques híbridos.

## Considerações de Segurança

É importante ressaltar que a quebra de hashes do Windows é uma atividade ilegal, a menos que seja realizada com permissão explícita do proprietário do sistema. A utilização dessas técnicas sem autorização pode resultar em consequências legais graves.

Além disso, é fundamental que os usuários escolham senhas fortes e únicas para evitar que seus hashes sejam quebrados facilmente. O uso de senhas complexas, combinadas com autenticação de dois fatores, pode ajudar a proteger as contas de usuário contra ataques de quebra de hashes.
```
3000 | LM                                               | Operating-Systems
1000 | NTLM                                             | Operating-Systems
```
# Quebrando Hashes de Aplicativos Comuns

## Introdução

Uma das técnicas mais comuns usadas pelos hackers para obter acesso não autorizado a contas é a quebra de hashes de senhas. Um hash é uma sequência de caracteres gerada a partir de uma senha usando um algoritmo de hash. Ao quebrar o hash, o hacker pode descobrir a senha original e, assim, obter acesso à conta.

Neste guia, vamos nos concentrar em quebrar hashes de senhas de aplicativos comuns. Vamos explorar algumas metodologias e recursos genéricos que podem ser usados para realizar essa tarefa.

## Metodologias Genéricas

### Ataques de Força Bruta

Um dos métodos mais simples e diretos para quebrar hashes de senhas é o ataque de força bruta. Nesse tipo de ataque, o hacker tenta todas as combinações possíveis de caracteres até encontrar a senha correta que corresponde ao hash.

Existem várias ferramentas disponíveis que podem automatizar esse processo, como o John the Ripper e o Hashcat. Essas ferramentas utilizam dicionários de palavras e regras de combinação para acelerar o processo de quebra de senha.

### Ataques de Dicionário

Os ataques de dicionário são semelhantes aos ataques de força bruta, mas em vez de tentar todas as combinações possíveis, eles usam uma lista de palavras comuns ou senhas conhecidas para tentar quebrar o hash. Essa abordagem é mais rápida do que o ataque de força bruta, pois reduz o espaço de busca.

Existem várias listas de palavras disponíveis na internet que podem ser usadas para realizar ataques de dicionário. Além disso, as ferramentas mencionadas anteriormente, como o John the Ripper e o Hashcat, também suportam ataques de dicionário.

### Ataques de Rainbow Table

Os ataques de rainbow table são uma abordagem mais avançada para quebrar hashes de senhas. Nesse tipo de ataque, o hacker usa uma tabela precomputada de hashes e senhas correspondentes, conhecida como rainbow table. Essa tabela permite que o hacker encontre rapidamente a senha correspondente a um determinado hash, sem a necessidade de calcular o hash para cada tentativa.

Existem várias rainbow tables disponíveis na internet para diferentes algoritmos de hash. No entanto, essas tabelas podem ocupar muito espaço em disco e exigir muito tempo para serem geradas.

## Recursos Genéricos

### John the Ripper

O John the Ripper é uma das ferramentas mais populares para quebrar hashes de senhas. Ele suporta vários tipos de hashes e pode ser executado em diferentes sistemas operacionais. Além disso, o John the Ripper possui recursos avançados, como suporte a dicionários personalizados e regras de combinação.

### Hashcat

O Hashcat é outra ferramenta poderosa para quebrar hashes de senhas. Ele suporta uma ampla variedade de algoritmos de hash e pode ser executado em GPUs para acelerar o processo de quebra de senha. O Hashcat também possui recursos avançados, como suporte a ataques de dicionário e rainbow table.

## Conclusão

Quebrar hashes de senhas de aplicativos comuns é uma técnica comum usada pelos hackers para obter acesso não autorizado. Neste guia, exploramos algumas metodologias genéricas e recursos populares que podem ser usados para realizar essa tarefa. É importante lembrar que a quebra de hashes de senhas é uma atividade ilegal, a menos que seja realizada com permissão explícita do proprietário da conta.
```
900 | MD4                                              | Raw Hash
0 | MD5                                              | Raw Hash
5100 | Half MD5                                         | Raw Hash
100 | SHA1                                             | Raw Hash
10800 | SHA-384                                          | Raw Hash
1400 | SHA-256                                          | Raw Hash
1700 | SHA-512                                          | Raw Hash
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com facilidade, utilizando as ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
