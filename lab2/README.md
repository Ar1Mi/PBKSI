# PBKSI — Laboratorium 2

**Uwierzytelnianie za pomocą protokołu Kerberos**

Artur Gubanovich, 25.10.2026
Środowisko: macOS (arm64), Docker 27.5 (Colima), obrazy `debian:bookworm`, MIT Kerberos 1.20.1, OpenSSH 9.2p1

Kilka słów na początek:

- Zamiast dwóch maszyn wirtualnych używam dwóch kontenerów Dockera w jednej sieci ([docker-compose.yml](docker-compose.yml)):
  - `kerberos.uws.edu.pl` — serwer uwierzytelniający (KDC + kadmind) i jednocześnie serwer SSH,
  - `client.uws.edu.pl` — klient Kerberosa i klient SSH.
- Kontenery startują z czystego Debiana — wszystkie pakiety instaluję w trakcie ćwiczenia, tak jak w instrukcji.
- Cały przebieg jest w skrypcie [run.sh](run.sh), który usuwa stare kontenery, tworzy nowe i wykonuje po kolei wszystkie polecenia. Pełny wynik jest w pliku [wynik.log](wynik.log), pełny wynik `ssh -v` w [client/ssh_debug.log](client/ssh_debug.log). Tutaj pokazuję tylko to, co istotne. Żeby powtórzyć ćwiczenie, wystarczy `./run.sh`.
- Moje pliki konfiguracyjne leżą w [server/etc](server/etc) i [client/etc](client/etc). Kontenery widzą je jako `/lab/etc`, skąd kopiuję je na właściwe miejsca.
- Hasło do master key bazy Kerberosa i do uczestników `student`, `student/admin` to `uwsii`.
- Baza KDC, plik `stash` i keytab usługi `host/` po zakończeniu skryptu są skopiowane do [server/artefakty](server/artefakty), żeby można je było sprawdzić.

## Zadanie 1. Instalacja serwera

**Nazwa maszyny**

Nazwę ustawiam w `docker-compose.yml` (`hostname: kerberos.uws.edu.pl`). W kontenerze nie da się wywołać `hostname nowa_nazwa` bez dodatkowych uprawnień, ale efekt jest ten sam:

```console
root@kerberos:~# hostname; hostname -f; cat /etc/hostname; grep kerberos /etc/hosts
kerberos.uws.edu.pl
kerberos.uws.edu.pl
kerberos.uws.edu.pl
172.21.0.2	kerberos.uws.edu.pl kerberos
```

Instrukcja proponuje wpis `127.0.0.1 kerberos.uws.edu.pl` w `/etc/hosts`. To wystarcza, gdy wszystko jest na jednej maszynie. U mnie klient jest osobnym hostem, więc nazwa musi wskazywać prawdziwy adres serwera w sieci — Docker sam dopisuje go do `/etc/hosts`, a na kliencie nazwę rozwiązuje wbudowany DNS Dockera (alias sieciowy).

**Instalacja pakietów**

Instalator `krb5-config` pyta o nazwę domeny, adres KDC i adres serwera administracyjnego. Odpowiedzi podaję z góry przez `debconf-set-selections`, żeby instalacja przeszła bez okien dialogowych:

```console
root@kerberos:~# cat <<EOF | debconf-set-selections
krb5-config krb5-config/default_realm string REALM.KB.UWS.EDU.PL
krb5-config krb5-config/kerberos_servers string kerberos.uws.edu.pl
krb5-config krb5-config/admin_server string kerberos.uws.edu.pl
...
EOF
root@kerberos:~# apt-get install -y ntp krb5-kdc krb5-admin-server openssh-server
root@kerberos:~# dpkg -l ntp ntpsec krb5-kdc krb5-admin-server openssh-server | tail -5
ii  krb5-admin-server 1.20.1-2+deb12u5                        arm64        MIT Kerberos master server (kadmind)
ii  krb5-kdc          1.20.1-2+deb12u5                        arm64        MIT Kerberos key server (KDC)
ii  ntp               1:4.2.8p15+dfsg-2~1.2.2+dfsg1-1+deb12u1 all          Network Time Protocol daemon/utilities (transitional package)
ii  ntpsec            1.2.2+dfsg1-1+deb12u1                   arm64        Network Time Protocol daemon and utility programs
ii  openssh-server    1:9.2p1-2+deb12u10                      arm64        secure shell (SSH) server, for secure access from remote machines
```

**NTP**

W Debianie 12 pakiet `ntp` jest już tylko pakietem przejściowym — instaluje `ntpsec`, a usługa nazywa się `ntpsec`, nie `ntp`:

```console
root@kerberos:~# service ntpsec start; service ntpsec status
Starting NTP server: ntpd ... ntpd ntpsec-1.2.2: Starting
NTP server is running.
```

Po chwili ntpd wybiera źródło czasu (gwiazdka w pierwszej kolumnie):

```console
root@kerberos:~# ntpq -pn | grep -E "remote|^=|^\*"; date
     remote           refid      st t when poll reach   delay   offset   jitter
===============================================================================
*109.206.205.239 .GPS.            1 u    3   64    1  46.4196 118.6470   5.7767
Sun Oct 25 09:23:39 UTC 2026
```

Synchronizacja czasu jest dla Kerberosa konieczna: bilety mają znacznik czasu i okres ważności, a KDC i usługi odrzucają żądania, w których czas różni się od ich własnego o więcej niż 5 minut (ochrona przed powtórzeniem). Żeby ntpd w kontenerze mógł w ogóle korygować zegar, kontener dostał uprawnienia `SYS_TIME`, `SYS_NICE` i `IPC_LOCK` (bez nich ntpd kończy działanie zaraz po starcie).

## Zadanie 2. Konfiguracja serwera

**krb5.conf** ([server/etc/krb5.conf](server/etc/krb5.conf))

Debian po instalacji generuje długi plik z przykładowymi domenami MIT. Zastąpiłem go własnym, krótkim:

```ini
[libdefaults]
        default_realm = REALM.KB.UWS.EDU.PL
        rdns = false
        dns_lookup_kdc = false
        dns_lookup_realm = false
        forwardable = true

[realms]
        REALM.KB.UWS.EDU.PL = {
                kdc = kerberos.uws.edu.pl
                admin_server = kerberos.uws.edu.pl
        }

[domain_realm]
        kerberos.uws.edu.pl = REALM.KB.UWS.EDU.PL
        .uws.edu.pl = REALM.KB.UWS.EDU.PL

[logging]
        kdc = FILE:/var/log/krb5kdc.log
        admin_server = FILE:/var/log/kadmin.log
        default = FILE:/var/log/krb5lib.log
```

W stosunku do przykładu z instrukcji dodałem:
- `rdns = false` — biblioteka nie zamienia adresu IP serwera z powrotem na nazwę. W Dockerze odwrotny DNS zwraca nazwę kontenera (`lab2-kerberos-1...`), a nie `kerberos.uws.edu.pl`, i klient prosiłby o bilet dla złego uczestnika `host/`.
- `dns_lookup_*` = false — KDC jest wskazany wprost, bez szukania rekordów SRV.
- `[logging]` — w kontenerze nie ma sysloga, więc dzienniki idą do plików.

**kdc.conf** ([server/etc/kdc.conf](server/etc/kdc.conf))

```ini
[kdcdefaults]
    kdc_ports = 750,88

[realms]
    REALM.KB.UWS.EDU.PL = {
        database_name = /var/lib/krb5kdc/principal
        admin_keytab = FILE:/etc/krb5kdc/kadm5.keytab
        acl_file = /etc/krb5kdc/kadm5.acl
        key_stash_file = /etc/krb5kdc/stash
        kdc_ports = 750,88
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        master_key_type = aes256-cts-hmac-sha1-96
        supported_enctypes = aes256-cts:normal aes128-cts:normal
        default_principal_flags = +preauth
    }
```

Jedyna świadoma zmiana względem instrukcji: `master_key_type = aes256-cts-hmac-sha1-96` zamiast `des3-hmac-sha1`. 3DES jest w MIT Kerberos oznaczony jako przestarzały (w logu KDC widać go jako `DEPRECATED:des3-cbc-sha1`), więc klucz główny i klucze uczestników są w AES. Odkomentowałem też `supported_enctypes`, żeby uczestnicy dostawali klucze AES-256 i AES-128.

**Baza danych**

W instrukcji przy `–s` jest długi myślnik zamiast zwykłego — trzeba wpisać `-s`. Opcja `-s` tworzy plik `stash` z kluczem głównym, dzięki czemu KDC startuje bez pytania o hasło. `-P` podaje hasło do klucza głównego.

```console
root@kerberos:~# kdb5_util create -r REALM.KB.UWS.EDU.PL -s -P uwsii
Initializing database '/var/lib/krb5kdc/principal' for realm 'REALM.KB.UWS.EDU.PL',
master key name 'K/M@REALM.KB.UWS.EDU.PL'

root@kerberos:~# ls -l /var/lib/krb5kdc /etc/krb5kdc
/etc/krb5kdc:
-rw-r--r-- 1 root root 527 Oct 25 09:23 kdc.conf
-rw------- 1 root root  84 Oct 25 09:23 stash

/var/lib/krb5kdc:
-rw------- 1 root root 8192 Oct 25 09:23 principal
-rw------- 1 root root 8192 Oct 25 09:23 principal.kadm5
-rw------- 1 root root    0 Oct 25 09:23 principal.kadm5.lock
-rw------- 1 root root    0 Oct 25  2026 principal.ok
```

Wszystkie cztery pliki wymienione w instrukcji (`principal`, `principal.kadm5`, `principal.kadm5.lock`, `principal.ok`) zostały utworzone.

## Zadanie 3. Zarządzanie użytkownikami

**Uprawnienia administracyjne i uruchomienie usług**

```console
root@kerberos:~# cat /etc/krb5kdc/kadm5.acl
*/admin@REALM.KB.UWS.EDU.PL *

root@kerberos:~# service krb5-kdc start; service krb5-admin-server start
Starting Kerberos KDC: krb5kdc.
Starting Kerberos administrative servers: kadmind.

root@kerberos:~# service krb5-kdc status; service krb5-admin-server status
krb5kdc is running.
kadmind is running.
```

ACL ustawiam przed startem `kadmind`, więc nie trzeba go potem restartować.

**Uczestnicy**

W instrukcji w znaku zachęty jest `admin.local:` — to literówka, program nazywa się `kadmin.local`. Polecenia podaję opcją `-q`, żeby nadawały się do skryptu:

```console
root@kerberos:~# kadmin.local -q 'addprinc -pw uwsii student/admin'
Principal "student/admin@REALM.KB.UWS.EDU.PL" created.

root@kerberos:~# kadmin.local -q 'addprinc -pw uwsii student'
Principal "student@REALM.KB.UWS.EDU.PL" created.

root@kerberos:~# kadmin.local -q 'addprinc -randkey host/kerberos.uws.edu.pl'
Principal "host/kerberos.uws.edu.pl@REALM.KB.UWS.EDU.PL" created.

root@kerberos:~# kadmin.local -q 'ktadd host/kerberos.uws.edu.pl'
Entry for principal host/kerberos.uws.edu.pl with kvno 2, encryption type aes256-cts-hmac-sha1-96 added to keytab FILE:/etc/krb5.keytab.
Entry for principal host/kerberos.uws.edu.pl with kvno 2, encryption type aes128-cts-hmac-sha1-96 added to keytab FILE:/etc/krb5.keytab.
```

- `student/admin` — uczestnik z rolą administratora. Pasuje do wzorca `*/admin` w `kadm5.acl`, więc ma pełne prawa do zarządzania domeną.
- `student` — zwykły uczestnik, na niego będzie logowanie przez SSH.
- `host/kerberos.uws.edu.pl` — uczestnik-usługa dla serwera SSH. Ma losowy klucz (`-randkey`), bo nikt nie wpisuje dla niego hasła. `ktadd` zapisuje ten klucz do `/etc/krb5.keytab`, z którego korzysta `sshd`. Numer wersji klucza (kvno) to 2, bo `ktadd` od razu losuje nowy klucz.

**Lista uczestników**

```console
root@kerberos:~# kadmin.local -q 'listprincs'
K/M@REALM.KB.UWS.EDU.PL
host/kerberos.uws.edu.pl@REALM.KB.UWS.EDU.PL
kadmin/admin@REALM.KB.UWS.EDU.PL
kadmin/changepw@REALM.KB.UWS.EDU.PL
krbtgt/REALM.KB.UWS.EDU.PL@REALM.KB.UWS.EDU.PL
student/admin@REALM.KB.UWS.EDU.PL
student@REALM.KB.UWS.EDU.PL
```

Oprócz moich trzech uczestników są tu uczestnicy utworzeni automatycznie razem z bazą: `K/M` (klucz główny bazy), `krbtgt/...` (klucz, którym KDC szyfruje bilety TGT) oraz `kadmin/admin` i `kadmin/changepw` (usługi serwera administracyjnego).

```console
root@kerberos:~# kadmin.local -q 'getprinc student'
Principal: student@REALM.KB.UWS.EDU.PL
Maximum ticket life: 0 days 10:00:00
Maximum renewable life: 7 days 00:00:00
Number of keys: 2
Key: vno 1, aes256-cts-hmac-sha1-96
Key: vno 1, aes128-cts-hmac-sha1-96
Attributes: REQUIRES_PRE_AUTH
...

root@kerberos:~# klist -ke /etc/krb5.keytab
Keytab name: FILE:/etc/krb5.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   2 host/kerberos.uws.edu.pl@REALM.KB.UWS.EDU.PL (aes256-cts-hmac-sha1-96)
   2 host/kerberos.uws.edu.pl@REALM.KB.UWS.EDU.PL (aes128-cts-hmac-sha1-96)
```

Widać, że ustawienia z `kdc.conf` zostały zastosowane: bilet ważny 10 h, odnawialny 7 dni, klucze AES i wymagane uwierzytelnienie wstępne (`+preauth` → `REQUIRES_PRE_AUTH`).

**kadmin przez sieć**

Dla sprawdzenia, że administrator i ACL działają, ta sama lista przez `kadmin` (przez sieć, z uwierzytelnieniem Kerberosa jako `student/admin`):

```console
root@kerberos:~# kadmin -p student/admin -w uwsii -q 'listprincs'
Authenticating as principal student/admin with password.
K/M@REALM.KB.UWS.EDU.PL
host/kerberos.uws.edu.pl@REALM.KB.UWS.EDU.PL
...
student@REALM.KB.UWS.EDU.PL
```

## Zadanie 4. Zarządzanie usługami (SSH)

Ustawienia dla `sshd` dodaję jako osobny plik w `/etc/ssh/sshd_config.d/` ([server/etc/sshd_kerberos.conf](server/etc/sshd_kerberos.conf)), żeby nie zmieniać głównego `sshd_config`:

```console
root@kerberos:~# cat /etc/ssh/sshd_config.d/kerberos.conf
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
GSSAPIKeyExchange yes

root@kerberos:~# useradd -m -s /bin/bash student && id student
uid=1000(student) gid=1000(student) groups=1000(student)

root@kerberos:~# service ssh start && sshd -t && service ssh status
Starting OpenBSD Secure Shell server: sshd.
sshd is running.

root@kerberos:~# sshd -T | grep -i gssapi
gssapiauthentication yes
gssapicleanupcredentials yes
gssapikeyexchange yes
gssapistrictacceptorcheck yes
...
```

- `GSSAPIAuthentication yes` — włącza uwierzytelnianie użytkownika biletem Kerberosa (metoda `gssapi-with-mic`).
- `GSSAPICleanupCredentials yes` — po wylogowaniu usuwa przekazane dane uwierzytelniające.
- `GSSAPIKeyExchange yes` — dodatkowo włącza wymianę kluczy GSSAPI (metoda `gssapi-keyex`). Ta opcja istnieje tylko dzięki łatce GSSAPI w OpenSSH Debiana. Instrukcja włącza ją po stronie klienta, a żeby została użyta, musi być włączona po obu stronach.
- `gssapistrictacceptorcheck yes` (domyślnie) — `sshd` przyjmuje tylko bilety dla uczestnika `host/<własna nazwa hosta>`, czyli właśnie `host/kerberos.uws.edu.pl`. Dlatego nazwa maszyny musi się zgadzać z uczestnikiem w keytabie.

Użytkownik `student` w systemie nie ma żadnego hasła — dostęp ma mieć wyłącznie przez Kerberosa. W kontenerze nie ma sysloga, więc w `/etc/default/ssh` ustawiłem `SSHD_OPTS="-E /var/log/sshd.log"`, żeby dziennik `sshd` trafiał do pliku.

## Zadanie 5. Uwierzytelnianie przez usługę Kerberosa

**Klient: instalacja i konfiguracja**

```console
root@client:~# hostname -f; getent hosts kerberos.uws.edu.pl
client.uws.edu.pl
172.21.0.2      kerberos.uws.edu.pl

root@client:~# apt-get install -y ntp krb5-user openssh-client
root@client:~# dpkg -l ntp ntpsec krb5-user openssh-client | tail -4
ii  krb5-user      1.20.1-2+deb12u5                        arm64        basic programs to authenticate using MIT Kerberos
ii  ntp            1:4.2.8p15+dfsg-2~1.2.2+dfsg1-1+deb12u1 all          Network Time Protocol daemon/utilities (transitional package)
ii  ntpsec         1.2.2+dfsg1-1+deb12u1                   arm64        Network Time Protocol daemon and utility programs
ii  openssh-client 1:9.2p1-2+deb12u10                      arm64        secure shell (SSH) client, for secure access to remote machines

root@client:~# service ntpsec start; service ntpsec status
NTP server is running.
```

Uwaga o NTP na kliencie: kontenery to nie są osobne maszyny, tylko procesy na jednym jądrze (maszyna wirtualna Colima), więc mają wspólny zegar systemowy. Zegar jest już synchronizowany przez ntpd na serwerze, a ntpd na kliencie tylko odpytuje serwery czasu (pełna tabela `ntpq -pn` jest w logu). Na dwóch prawdziwych maszynach każda synchronizowałaby własny zegar.

Na kliencie `/etc/krb5.conf` jest taki sam jak na serwerze ([client/etc/krb5.conf](client/etc/krb5.conf)). Ustawienia SSH ([client/etc/ssh_kerberos.conf](client/etc/ssh_kerberos.conf)):

```console
root@client:~# cat /etc/ssh/ssh_config.d/kerberos.conf
Host *
    GSSAPIAuthentication yes
    GSSAPIKeyExchange yes
```

Klucz hosta serwera dodaję do `known_hosts` przez `ssh-keyscan`, żeby SSH nie pytał o akceptację odcisku. Klient łączy się w trybie `-o BatchMode=yes`, w którym SSH nigdy nie pyta o hasło. Logowanie może się więc udać tylko bez hasła.

**Próba bez biletu**

```console
root@client:~# klist; ssh -o BatchMode=yes student@kerberos.uws.edu.pl hostname
klist: No credentials cache found (filename: /tmp/krb5cc_0)
student@kerberos.uws.edu.pl: Permission denied (publickey,gssapi-keyex,gssapi-with-mic,password).
```

Bez biletu serwer odmawia. Na liście metod widać `gssapi-keyex` i `gssapi-with-mic`, czyli serwer oferuje uwierzytelnianie Kerberosem.

**Bilet dla użytkownika student**

```console
root@client:~# kinit student
Password for student@REALM.KB.UWS.EDU.PL:

root@client:~# klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: student@REALM.KB.UWS.EDU.PL

Valid starting     Expires            Service principal
10/25/26 09:24:13  10/25/26 19:24:13  krbtgt/REALM.KB.UWS.EDU.PL@REALM.KB.UWS.EDU.PL
	renew until 10/26/26 09:24:13
```

Klient dostał bilet TGT (`krbtgt/...`) ważny 10 godzin i odnawialny do następnego dnia. Hasło wpisuje się tylko ten jeden raz, przy `kinit`.

**Logowanie przez SSH**

```console
root@client:~# ssh -v -o BatchMode=yes student@kerberos.uws.edu.pl "whoami; hostname -f"
student
kerberos.uws.edu.pl
```

Najważniejsze linie z `ssh -v` (pełny wynik: [client/ssh_debug.log](client/ssh_debug.log)):

```text
debug1: Authenticating to kerberos.uws.edu.pl:22 as 'student'
debug1: Offering GSSAPI proposal: gss-group14-sha256-toWM5Slw5Ew8Mqkay+al2g==,gss-group16-sha512-toWM5Slw5Ew8Mqkay+al2g==,...
debug1: kex: algorithm: gss-group14-sha256-toWM5Slw5Ew8Mqkay+al2g==
debug1: Authentications that can continue: publickey,gssapi-keyex,gssapi-with-mic,password
debug1: Next authentication method: gssapi-keyex
Authenticated to kerberos.uws.edu.pl ([172.21.0.2]:22) using "gssapi-keyex".
```

To są te same komunikaty, które pokazuje instrukcja: klient proponuje algorytmy wymiany kluczy GSSAPI (`gss-...-toWM5Slw5Ew8Mqkay+al2g==`, sufiks to skrót identyfikatora mechanizmu Kerberos 5), serwer wybiera jeden z nich, a użytkownik jest uwierzytelniony metodą `gssapi-keyex` — bez hasła.

Po zalogowaniu w pamięci podręcznej klienta jest drugi bilet — bilet usługi dla serwera SSH, pobrany z KDC na podstawie TGT:

```console
root@client:~# klist
Default principal: student@REALM.KB.UWS.EDU.PL

Valid starting     Expires            Service principal
10/25/26 09:24:13  10/25/26 19:24:13  krbtgt/REALM.KB.UWS.EDU.PL@REALM.KB.UWS.EDU.PL
	renew until 10/26/26 09:24:13
10/25/26 09:24:13  10/25/26 19:24:13  host/kerberos.uws.edu.pl@REALM.KB.UWS.EDU.PL
	renew until 10/26/26 09:24:13
```

**To samo bez wymiany kluczy GSSAPI**

Dla porównania wyłączyłem `GSSAPIKeyExchange` po stronie klienta. Wymiana kluczy jest wtedy zwykła (`sntrup761x25519-sha512`), a Kerberos służy tylko do uwierzytelnienia użytkownika:

```console
root@client:~# ssh -v -o BatchMode=yes -o GSSAPIKeyExchange=no student@kerberos.uws.edu.pl id
debug1: kex: algorithm: sntrup761x25519-sha512
debug1: Next authentication method: gssapi-with-mic
Authenticated to kerberos.uws.edu.pl ([172.21.0.2]:22) using "gssapi-with-mic".
uid=1000(student) gid=1000(student) groups=1000(student)
```

**Co widzi serwer**

Dziennik KDC — najpierw wydanie TGT (`AS_REQ`), potem biletu na usługę `host/` (`TGS_REQ`), oba dla klienta 172.21.0.3 (skrócone):

```text
krb5kdc[4341](info): AS_REQ (...) 172.21.0.3: ISSUE: authtime 1792920253, etypes {rep=aes256-cts-hmac-sha1-96(18), tkt=aes256-cts-hmac-sha1-96(18), ses=aes256-cts-hmac-sha1-96(18)}, student@REALM.KB.UWS.EDU.PL for krbtgt/REALM.KB.UWS.EDU.PL@REALM.KB.UWS.EDU.PL
krb5kdc[4341](info): TGS_REQ (...) 172.21.0.3: ISSUE: authtime 1792920253, etypes {rep=aes256-cts-hmac-sha1-96(18), tkt=aes256-cts-hmac-sha1-96(18), ses=aes256-cts-hmac-sha1-96(18)}, student@REALM.KB.UWS.EDU.PL for host/kerberos.uws.edu.pl@REALM.KB.UWS.EDU.PL
```

Dziennik `sshd`:

```console
root@kerberos:~# grep -E "Accepted|Authorized" /var/log/sshd.log
Authorized to student, krb5 principal student@REALM.KB.UWS.EDU.PL (krb5_kuserok)
Accepted gssapi-keyex for student from 172.21.0.3 port 51106 ssh2: student@REALM.KB.UWS.EDU.PL
Authorized to student, krb5 principal student@REALM.KB.UWS.EDU.PL (krb5_kuserok)
Accepted gssapi-with-mic for student from 172.21.0.3 port 51114 ssh2: student@REALM.KB.UWS.EDU.PL
```

`krb5_kuserok` to sprawdzenie, czy uczestnik Kerberosa może zalogować się na dane konto lokalne. Uczestnik `student@REALM.KB.UWS.EDU.PL` z domyślnej domeny odpowiada kontu `student`, więc dostęp jest przyznany.

**Po usunięciu biletu**

```console
root@client:~# kdestroy && klist; ssh -o BatchMode=yes student@kerberos.uws.edu.pl hostname
klist: No credentials cache found (filename: /tmp/krb5cc_0)
student@kerberos.uws.edu.pl: Permission denied (publickey,gssapi-keyex,gssapi-with-mic,password).
```

Bez biletu dostępu znowu nie ma, czyli logowanie rzeczywiście zależało od Kerberosa.

## Podsumowanie

Uruchomiłem domenę Kerberosa `REALM.KB.UWS.EDU.PL` z KDC i serwerem administracyjnym na `kerberos.uws.edu.pl` oraz dodałem uczestników `student`, `student/admin` i `host/kerberos.uws.edu.pl`. Serwer SSH przyjmuje bilety Kerberosa. Z drugiej maszyny, po jednorazowym `kinit student`, użytkownik loguje się przez `ssh student@kerberos.uws.edu.pl` bez podawania hasła — zarówno metodą `gssapi-keyex`, jak i `gssapi-with-mic`. Bez ważnego biletu dostęp jest blokowany.

Odstępstwa od instrukcji, w skrócie:
- dwa kontenery Dockera zamiast dwóch maszyn,
- `ntpsec` zamiast `ntp` (w Debianie 12 `ntp` to tylko pakiet przejściowy),
- `aes256-cts` zamiast `des3-hmac-sha1` jako typ klucza głównego,
- adres serwera w `/etc/hosts` to adres w sieci Dockera, a nie `127.0.0.1`,
- w `krb5.conf` dodane `rdns = false`, bo odwrotny DNS Dockera zwraca nazwę kontenera.
