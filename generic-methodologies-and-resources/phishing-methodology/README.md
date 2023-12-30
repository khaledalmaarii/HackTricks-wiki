# Metodologia de Phishing

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Metodologia

1. Reconheça a vítima
   1. Selecione o **domínio da vítima**.
   2. Realize uma enumeração básica da web **procurando por portais de login** usados pela vítima e **decida** qual você vai **impersonar**.
   3. Use **OSINT** para **encontrar emails**.
2. Prepare o ambiente
   1. **Compre o domínio** que você usará para a avaliação de phishing
   2. **Configure o serviço de email** relacionado aos registros (SPF, DMARC, DKIM, rDNS)
   3. Configure o VPS com **gophish**
3. Prepare a campanha
   1. Prepare o **template de email**
   2. Prepare a **página web** para roubar as credenciais
4. Lance a campanha!

## Gerar nomes de domínio similares ou comprar um domínio confiável

### Técnicas de Variação de Nome de Domínio

* **Palavra-chave**: O nome do domínio **contém** uma palavra-chave importante do domínio original (ex.: zelster.com-management.com).
* **subdomínio com hífen**: Troque o **ponto por um hífen** de um subdomínio (ex.: www-zelster.com).
* **Novo TLD**: Mesmo domínio usando um **novo TLD** (ex.: zelster.org)
* **Homoglyph**: **Substitui** uma letra no nome do domínio por **letras que parecem semelhantes** (ex.: zelfser.com).
* **Transposição**: **Troca duas letras** dentro do nome do domínio (ex.: zelster.com).
* **Singularização/Pluralização**: Adiciona ou remove “s” no final do nome do domínio (ex.: zeltsers.com).
* **Omissão**: **Remove uma** das letras do nome do domínio (ex.: zelser.com).
* **Repetição**: **Repete uma** das letras no nome do domínio (ex.: zeltsser.com).
* **Substituição**: Como homoglyph, mas menos discreto. Substitui uma das letras no nome do domínio, talvez por uma letra próxima da original no teclado (ex.: zektser.com).
* **Subdominado**: Introduz um **ponto** dentro do nome do domínio (ex.: ze.lster.com).
* **Inserção**: **Insere uma letra** no nome do domínio (ex.: zerltser.com).
* **Ponto ausente**: Anexa o TLD ao nome do domínio. (ex.: zelstercom.com)

**Ferramentas Automáticas**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

No mundo da computação, tudo é armazenado em bits (zeros e uns) na memória por trás das cenas.\
Isso se aplica a domínios também. Por exemplo, _windows.com_ se torna _01110111..._ na memória volátil do seu dispositivo de computação.\
No entanto, e se um desses bits fosse automaticamente invertido devido a uma tempestade solar, raios cósmicos ou um erro de hardware? Ou seja, um dos 0's se torna um 1 e vice-versa.\
Aplicando esse conceito a uma solicitação de DNS, é possível que o **domínio solicitado** que chega ao servidor DNS **não seja o mesmo que o domínio inicialmente solicitado.**

Por exemplo, uma modificação de 1 bit no domínio windows.com pode transformá-lo em _windnws.com._\
**Os atacantes podem registrar tantos domínios de bit-flipping quanto possível relacionados à vítima para redirecionar usuários legítimos para sua infraestrutura**.

Para mais informações, leia [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Comprar um domínio confiável

Você pode procurar em [https://www.expireddomains.net/](https://www.expireddomains.net) por um domínio expirado que você poderia usar.\
Para garantir que o domínio expirado que você vai comprar **já tenha um bom SEO**, você pode verificar como ele está categorizado em:

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Descobrindo Emails

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% grátis)
* [https://phonebook.cz/](https://phonebook.cz) (100% grátis)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

Para **descobrir mais** endereços de email válidos ou **verificar os que** você já descobriu, você pode verificar se consegue forçar a entrada nos servidores smtp da vítima. [Aprenda como verificar/descobrir endereços de email aqui](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration).\
Além disso, não esqueça que se os usuários usam **qualquer portal web para acessar seus emails**, você pode verificar se é vulnerável a **força bruta de nome de usuário**, e explorar a vulnerabilidade se possível.

## Configurando GoPhish

### Instalação

Você pode baixá-lo de [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Baixe e descomprima dentro de `/opt/gophish` e execute `/opt/gophish/gophish`\
Você receberá uma senha para o usuário admin na porta 3333 na saída. Portanto, acesse essa porta e use essas credenciais para alterar a senha do admin. Você pode precisar tunelar essa porta para local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuração

**Configuração do certificado TLS**

Antes deste passo, você deve **ter comprado o domínio** que vai usar e ele deve estar **apontando** para o **IP do VPS** onde você está configurando o **gophish**.
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**Configuração de E-mail**

Comece instalando: `apt-get install postfix`

Em seguida, adicione o domínio aos seguintes arquivos:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**Altere também os valores das seguintes variáveis dentro de /etc/postfix/main.cf**

`myhostname = <domínio>`\
`mydestination = $myhostname, <domínio>, localhost.com, localhost`

Finalmente, modifique os arquivos **`/etc/hostname`** e **`/etc/mailname`** para o nome do seu domínio e **reinicie seu VPS.**

Agora, crie um **registro DNS A** de `mail.<domínio>` apontando para o **endereço IP** do VPS e um registro **DNS MX** apontando para `mail.<domínio>`

Agora vamos testar enviar um e-mail:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Configuração do Gophish**

Pare a execução do gophish e vamos configurá-lo.\
Modifique `/opt/gophish/config.json` para o seguinte (observe o uso de https):
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**Configurar o serviço gophish**

Para criar o serviço gophish de modo que ele possa ser iniciado automaticamente e gerenciado como um serviço, você pode criar o arquivo `/etc/init.d/gophish` com o seguinte conteúdo:
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
Conclua a configuração do serviço e verifique fazendo:
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## Configurando servidor de e-mail e domínio

### Espera

Quanto mais antigo for um domínio, menor a probabilidade de ser marcado como spam. Então, você deve esperar o máximo de tempo possível (pelo menos 1 semana) antes da avaliação de phishing.\
Observe que, mesmo tendo que esperar uma semana, você pode terminar de configurar tudo agora.

### Configurar registro de DNS Reverso (rDNS)

Defina um registro rDNS (PTR) que resolva o endereço IP do VPS para o nome do domínio.

### Registro de Sender Policy Framework (SPF)

Você deve **configurar um registro SPF para o novo domínio**. Se você não sabe o que é um registro SPF [**leia esta página**](../../network-services-pentesting/pentesting-smtp/#spf).

Você pode usar [https://www.spfwizard.net/](https://www.spfwizard.net) para gerar sua política SPF (use o IP da máquina VPS)

![](<../../.gitbook/assets/image (388).png>)

Este é o conteúdo que deve ser definido dentro de um registro TXT no domínio:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Registro de Domain-based Message Authentication, Reporting & Conformance (DMARC)

Você deve **configurar um registro DMARC para o novo domínio**. Se você não sabe o que é um registro DMARC [**leia esta página**](../../network-services-pentesting/pentesting-smtp/#dmarc).

Você precisa criar um novo registro TXT DNS apontando o hostname `_dmarc.<domain>` com o seguinte conteúdo:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

Você deve **configurar um DKIM para o novo domínio**. Se você não sabe o que é um registro DMARC [**leia esta página**](../../network-services-pentesting/pentesting-smtp/#dkim).

Este tutorial é baseado em: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
Você precisa concatenar ambos os valores B64 que a chave DKIM gera:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### Teste a pontuação da configuração do seu email

Você pode fazer isso usando [https://www.mail-tester.com/](https://www.mail-tester.com)\
Acesse a página e envie um email para o endereço que eles fornecem:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
Você também pode **verificar a configuração do seu e-mail** enviando um e-mail para `check-auth@verifier.port25.com` e **lendo a resposta** (para isso você precisará **abrir** a porta **25** e ver a resposta no arquivo _/var/mail/root_ se você enviar o e-mail como root).\
Verifique se você passou em todos os testes:
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
Alternativamente, você pode enviar uma **mensagem para um endereço do Gmail que você controla**, **visualizar** os **cabeçalhos do email recebido** na sua caixa de entrada do Gmail, `dkim=pass` deve estar presente no campo `Authentication-Results` do cabeçalho.
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Removendo da Lista Negra do Spamhouse

A página www.mail-tester.com pode indicar se o seu domínio está sendo bloqueado pelo spamhouse. Você pode solicitar a remoção do seu domínio/IP em: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removendo da Lista Negra da Microsoft

Você pode solicitar a remoção do seu domínio/IP em [https://sender.office.com/](https://sender.office.com).

## Criar & Lançar Campanha GoPhish

### Perfil de Envio

* Defina um **nome para identificar** o perfil do remetente
* Decida de qual conta você vai enviar os e-mails de phishing. Sugestões: _noreply, support, servicedesk, salesforce..._
* Você pode deixar em branco o nome de usuário e a senha, mas certifique-se de marcar a opção Ignorar Erros de Certificado

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
É recomendado usar a funcionalidade "**Enviar E-mail de Teste**" para testar se tudo está funcionando.\
Eu recomendaria **enviar os e-mails de teste para endereços de 10min mails** para evitar ser colocado na lista negra ao fazer testes.
{% endhint %}

### Modelo de E-mail

* Defina um **nome para identificar** o modelo
* Em seguida, escreva um **assunto** (nada estranho, apenas algo que você esperaria ler em um e-mail comum)
* Certifique-se de ter marcado "**Adicionar Imagem de Rastreamento**"
* Escreva o **modelo de e-mail** (você pode usar variáveis como no exemplo a seguir):
```markup
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>

<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">As you may be aware, due to the large number of employees working from home, the "PLATFORM NAME" platform is being migrated to a new domain with an improved and more secure version. To finalize account migration, please use the following link to log into the new HR portal and move your account to the new site: <a href="{{.URL}}"> "PLATFORM NAME" login portal </a><br />
<br />
Please Note: We require all users to move their accounts by 04/01/2021. Failure to confirm account migration may prevent you from logging into the application after the migration process is complete.<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
Note que **para aumentar a credibilidade do email**, é recomendado usar alguma assinatura de um email do cliente. Sugestões:

* Envie um email para um **endereço inexistente** e verifique se a resposta tem alguma assinatura.
* Procure por **emails públicos** como info@ex.com ou press@ex.com ou public@ex.com e envie-lhes um email e aguarde pela resposta.
* Tente contactar **algum email válido descoberto** e aguarde pela resposta.

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
O Modelo de Email também permite **anexar arquivos para enviar**. Se você também quiser roubar desafios NTLM usando alguns arquivos/documentos especialmente criados [leia esta página](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).
{% endhint %}

### Página de Destino

* Escreva um **nome**
* **Escreva o código HTML** da página web. Note que você pode **importar** páginas web.
* Marque **Capturar Dados Submetidos** e **Capturar Senhas**
* Defina um **redirecionamento**

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
Geralmente você precisará modificar o código HTML da página e fazer alguns testes localmente (talvez usando algum servidor Apache) **até que goste dos resultados.** Então, escreva esse código HTML na caixa.\
Note que se você precisar **usar alguns recursos estáticos** para o HTML (talvez algumas páginas CSS e JS) você pode salvá-los em _**/opt/gophish/static/endpoint**_ e então acessá-los de _**/static/\<filename>**_
{% endhint %}

{% hint style="info" %}
Para o redirecionamento, você poderia **redirecionar os usuários para a página web principal legítima** da vítima, ou redirecioná-los para _/static/migration.html_ por exemplo, colocar algum **giro de espera (**[**https://loading.io/**](https://loading.io)**) por 5 segundos e então indicar que o processo foi bem-sucedido**.
{% endhint %}

### Usuários & Grupos

* Defina um nome
* **Importe os dados** (note que para usar o modelo para o exemplo você precisa do primeiro nome, sobrenome e endereço de email de cada usuário)

![](<../../.gitbook/assets/image (395).png>)

### Campanha

Finalmente, crie uma campanha selecionando um nome, o modelo de email, a página de destino, a URL, o perfil de envio e o grupo. Note que a URL será o link enviado às vítimas

Note que o **Perfil de Envio permite enviar um email de teste para ver como será a aparência do email de phishing final**:

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
Eu recomendaria **enviar os emails de teste para endereços de email de 10min** para evitar ser colocado na lista negra fazendo testes.
{% endhint %}

Uma vez que tudo esteja pronto, é só lançar a campanha!

## Clonagem de Website

Se por algum motivo você quiser clonar o website, verifique a seguinte página:

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## Documentos & Arquivos com Backdoor

Em algumas avaliações de phishing (principalmente para Red Teams) você vai querer também **enviar arquivos contendo algum tipo de backdoor** (talvez um C2 ou talvez apenas algo que acionará uma autenticação).\
Confira a seguinte página para alguns exemplos:

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## Phishing MFA

### Via Proxy MitM

O ataque anterior é bastante inteligente, pois você está falsificando um site real e coletando as informações definidas pelo usuário. Infelizmente, se o usuário não inserir a senha correta ou se o aplicativo que você falsificou estiver configurado com 2FA, **essas informações não permitirão que você se passe pelo usuário enganado**.

É aqui que ferramentas como [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) e [**muraena**](https://github.com/muraenateam/muraena) são úteis. Esta ferramenta permitirá que você gere um ataque tipo MitM. Basicamente, o ataque funciona da seguinte maneira:

1. Você **se passa pelo formulário de login** da página real.
2. O usuário **envia** suas **credenciais** para sua página falsa e a ferramenta as envia para a página real, **verificando se as credenciais funcionam**.
3. Se a conta estiver configurada com **2FA**, a página MitM pedirá por ela e, uma vez que o **usuário a introduza**, a ferramenta a enviará para a página real.
4. Uma vez que o usuário esteja autenticado, você (como atacante) terá **capturado as credenciais, o 2FA, o cookie e qualquer informação** de cada interação sua enquanto a ferramenta estiver realizando um MitM.

### Via VNC

E se, em vez de **enviar a vítima para uma página maliciosa** com a mesma aparência da original, você a enviar para uma **sessão VNC com um navegador conectado à página web real**? Você poderá ver o que ele faz, roubar a senha, o MFA usado, os cookies...\
Você pode fazer isso com [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detectando a detecção

Obviamente, uma das melhores maneiras de saber se você foi descoberto é **procurar seu domínio dentro de listas negras**. Se ele aparecer listado, de alguma forma seu domínio foi detectado como suspeito.\
Uma maneira fácil de verificar se o seu domínio aparece em alguma lista negra é usar [https://malwareworld.com/](https://malwareworld.com)

No entanto, existem outras maneiras de saber se a vítima está **procurando ativamente por atividades suspeitas de phishing na internet** como explicado em:

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

Você pode **comprar um domínio com um nome muito semelhante** ao domínio da vítima **e/ou gerar um certificado** para um **subdomínio** de um domínio controlado por você **contendo** a **palavra-chave** do domínio da vítima. Se a **vítima** realizar qualquer tipo de **interação DNS ou HTTP** com eles, você saberá que **ela está ativamente procurando** por domínios suspeitos e você precisará ser muito discreto.

### Avaliar o phishing

Use [**Phishious** ](https://github.com/Rices/Phishious) para avaliar se o seu email vai acabar na pasta de spam ou se será bloqueado ou bem-sucedido.

## Referências

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>
