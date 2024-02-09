# Como o Infravermelho Funciona <a href="#como-o-infravermelho-funciona" id="como-o-infravermelho-funciona"></a>

**A luz infravermelha é invisível para os humanos**. O comprimento de onda do IR varia de **0,7 a 1000 mícrons**. Os controles remotos domésticos usam um sinal IR para transmissão de dados e operam na faixa de comprimento de onda de 0,75 a 1,4 mícrons. Um microcontrolador no controle remoto faz um LED infravermelho piscar com uma frequência específica, transformando o sinal digital em um sinal IR.

Para receber sinais IR, é usado um **fotorreceptor**. Ele **converte a luz IR em pulsos de tensão**, que já são **sinais digitais**. Geralmente, há um **filtro de luz escura dentro do receptor**, que permite passar apenas o comprimento de onda desejado e elimina o ruído.

### Variedade de Protocolos IR <a href="#variedade-de-protocolos-ir" id="variedade-de-protocolos-ir"></a>

Os protocolos IR diferem em 3 fatores:

* codificação de bits
* estrutura de dados
* frequência do portador — frequentemente na faixa de 36 a 38 kHz

#### Formas de Codificação de Bits <a href="#formas-de-codificação-de-bits" id="formas-de-codificação-de-bits"></a>

**1. Codificação de Distância de Pulso**

Os bits são codificados modulando a duração do espaço entre pulsos. A largura do próprio pulso é constante.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

**2. Codificação de Largura de Pulso**

Os bits são codificados pela modulação da largura do pulso. A largura do espaço após o pulso é constante.

<figure><img src="../../.gitbook/assets/image (29) (1).png" alt=""><figcaption></figcaption></figure>

**3. Codificação de Fase**

Também conhecida como codificação Manchester. O valor lógico é definido pela polaridade da transição entre o pulso e o espaço. "Espaço para pulso" denota lógica "0", "pulso para espaço" denota lógica "1".

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

**4. Combinação dos anteriores e outros exóticos**

{% hint style="info" %}
Existem protocolos IR que estão **tentando se tornar universais** para vários tipos de dispositivos. Os mais famosos são RC5 e NEC. Infelizmente, os mais famosos **não significam os mais comuns**. Em meu ambiente, encontrei apenas dois controles remotos NEC e nenhum RC5.

Os fabricantes adoram usar seus próprios protocolos IR exclusivos, mesmo dentro da mesma faixa de dispositivos (por exemplo, set-top boxes). Portanto, controles remotos de diferentes empresas e às vezes de diferentes modelos da mesma empresa, não conseguem funcionar com outros dispositivos do mesmo tipo.
{% endhint %}

### Explorando um Sinal IR

A maneira mais confiável de ver como se parece o sinal IR do controle remoto é usar um osciloscópio. Ele não demodula ou inverte o sinal recebido, apenas o exibe "como está". Isso é útil para testes e depuração. Mostrarei o sinal esperado no exemplo do protocolo IR NEC.

<figure><img src="../../.gitbook/assets/image (18) (2).png" alt=""><figcaption></figcaption></figure>

Geralmente, há um preâmbulo no início de um pacote codificado. Isso permite ao receptor determinar o nível de ganho e o fundo. Existem também protocolos sem preâmbulo, por exemplo, Sharp.

Em seguida, os dados são transmitidos. A estrutura, preâmbulo e método de codificação de bits são determinados pelo protocolo específico.

O **protocolo IR NEC** contém um comando curto e um código de repetição, que é enviado enquanto o botão é pressionado. Tanto o comando quanto o código de repetição têm o mesmo preâmbulo no início.

O **comando NEC**, além do preâmbulo, consiste em um byte de endereço e um byte de número de comando, pelo qual o dispositivo entende o que precisa ser executado. Os bytes de endereço e número de comando são duplicados com valores inversos, para verificar a integridade da transmissão. Há um bit de parada adicional no final do comando.

O **código de repetição** tem um "1" após o preâmbulo, que é um bit de parada.

Para a lógica "0" e "1", a NEC usa a Codificação de Distância de Pulso: primeiro, é transmitido um pulso, após o qual há uma pausa, cujo comprimento define o valor do bit.

### Condicionadores de Ar

Ao contrário de outros controles remotos, **os condicionadores de ar não transmitem apenas o código do botão pressionado**. Eles também **transmitem todas as informações** quando um botão é pressionado para garantir que a **máquina de ar condicionado e o controle remoto estejam sincronizados**.\
Isso evita que uma máquina configurada para 20ºC seja aumentada para 21ºC com um controle remoto e, em seguida, quando outro controle remoto, que ainda tem a temperatura como 20ºC, é usado para aumentar mais a temperatura, ela "aumentará" para 21ºC (e não para 22ºC pensando que está em 21ºC).

### Ataques

Você pode atacar o Infravermelho com o Flipper Zero:

{% content-ref url="flipper-zero/fz-infrared.md" %}
[fz-infrared.md](flipper-zero/fz-infrared.md)
{% endcontent-ref %}

## Referências

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)
