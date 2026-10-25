#!/usr/bin/env bash
# Pełny przebieg laboratorium 2 od czystych kontenerów.
# Każde polecenie jest wypisywane razem z wynikiem do pliku wynik.log.
set -u
cd "$(dirname "$0")"
LOG=wynik.log
: > "$LOG"

PASS=uwsii
REALM=REALM.KB.UWS.EDU.PL

# srv / cli — wykonanie polecenia na serwerze / kliencie z zapisem do logu
run() {
    local host=$1 prompt=$2; shift 2
    printf '\n%s %s\n' "$prompt" "$*" | tee -a "$LOG"
    docker compose exec -T "$host" bash -c "$*" 2>&1 | tee -a "$LOG"
}
srv() { run kerberos 'root@kerberos:~#' "$@"; }
cli() { run client   'root@client:~#'   "$@"; }
section() { printf '\n\n===== %s =====\n' "$*" | tee -a "$LOG"; }

docker compose down -t 1 >/dev/null 2>&1
rm -rf server/artefakty
docker compose up -d >/dev/null 2>&1

APT='DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o=Dpkg::Use-Pty=0'
# odpowiedzi na pytania instalatora krb5-config (realm, KDC, serwer administracyjny)
DEBCONF="cat <<EOF | debconf-set-selections
krb5-config krb5-config/default_realm string $REALM
krb5-config krb5-config/kerberos_servers string kerberos.uws.edu.pl
krb5-config krb5-config/admin_server string kerberos.uws.edu.pl
krb5-config krb5-config/add_servers_realm string $REALM
krb5-config krb5-config/add_servers boolean true
krb5-config krb5-config/read_conf boolean true
EOF"

section 'Zadanie 1. Instalacja serwera'
srv 'hostname; hostname -f; cat /etc/hostname; grep kerberos /etc/hosts'
srv 'apt-get update -qq'
srv "$DEBCONF"
srv "$APT ntp krb5-kdc krb5-admin-server openssh-server >/tmp/apt.log 2>&1; echo \"apt: kod \$?\"; dpkg -l ntp ntpsec krb5-kdc krb5-admin-server openssh-server | tail -5"
srv 'service ntpsec start; sleep 3; service ntpsec status'
srv 'date'

section 'Zadanie 2. Konfiguracja serwera'
srv 'cp /lab/etc/krb5.conf /etc/krb5.conf && cat /etc/krb5.conf'
srv 'cp /lab/etc/kdc.conf /etc/krb5kdc/kdc.conf && cat /etc/krb5kdc/kdc.conf'
srv "kdb5_util create -r $REALM -s -P $PASS"
srv 'ls -l /var/lib/krb5kdc /etc/krb5kdc'

section 'Zadanie 3. Zarządzanie użytkownikami'
srv 'cp /lab/etc/kadm5.acl /etc/krb5kdc/kadm5.acl && cat /etc/krb5kdc/kadm5.acl'
srv 'service krb5-kdc start; service krb5-admin-server start'
srv 'service krb5-kdc status; service krb5-admin-server status'
srv "kadmin.local -q 'addprinc -pw $PASS student/admin'"
srv "kadmin.local -q 'addprinc -pw $PASS student'"
srv "kadmin.local -q 'addprinc -randkey host/kerberos.uws.edu.pl'"
srv "kadmin.local -q 'ktadd host/kerberos.uws.edu.pl'"
srv "kadmin.local -q 'listprincs'"
srv "kadmin.local -q 'getprinc student'"
srv 'klist -ke /etc/krb5.keytab'
# kadmin przez sieć, uwierzytelniony jako student/admin
srv "kadmin -p student/admin -w $PASS -q 'listprincs'"
srv "kinit student <<< $PASS && klist && kdestroy"

section 'Zadanie 4. Zarządzanie usługami (SSH)'
srv 'cp /lab/etc/sshd_kerberos.conf /etc/ssh/sshd_config.d/kerberos.conf && cat /etc/ssh/sshd_config.d/kerberos.conf'
srv 'useradd -m -s /bin/bash student && id student'
# w kontenerze nie ma sysloga — dziennik sshd kierujemy do pliku
srv 'echo SSHD_OPTS=\"-E /var/log/sshd.log\" >> /etc/default/ssh && service ssh start && sshd -t && service ssh status'
srv 'sshd -T | grep -i gssapi'

section 'Zadanie 5. Uwierzytelnianie przez usługę Kerberosa'
# czekamy (maks. 3 min), aż ntpd wybierze źródło czasu — oznaczone gwiazdką
srv 'for i in $(seq 36); do ntpq -pn | grep "^\*" >/dev/null && break; sleep 5; done; ntpq -pn | grep -E "remote|^=|^\*"; date'
cli 'hostname -f; getent hosts kerberos.uws.edu.pl'
cli 'apt-get update -qq'
cli "$DEBCONF"
cli "$APT ntp krb5-user openssh-client >/tmp/apt.log 2>&1; echo \"apt: kod \$?\"; dpkg -l ntp ntpsec krb5-user openssh-client | tail -4"
cli 'service ntpsec start; sleep 3; service ntpsec status; date'
cli 'cp /lab/etc/krb5.conf /etc/krb5.conf && cat /etc/krb5.conf'
cli 'cp /lab/etc/ssh_kerberos.conf /etc/ssh/ssh_config.d/kerberos.conf && cat /etc/ssh/ssh_config.d/kerberos.conf'
cli 'ssh-keyscan -t ed25519 kerberos.uws.edu.pl > ~/.ssh_known 2>/dev/null; mkdir -p ~/.ssh && mv ~/.ssh_known ~/.ssh/known_hosts'
# bez biletu — logowanie nie może się udać (BatchMode wyłącza pytanie o hasło)
cli 'klist; ssh -o BatchMode=yes student@kerberos.uws.edu.pl hostname'
cli "kinit student <<< $PASS"
cli 'klist'
# pełny wynik ssh -v trafia do client/ssh_debug.log, tutaj tylko najważniejsze linie
cli 'ssh -v -o BatchMode=yes student@kerberos.uws.edu.pl "whoami; hostname -f" 2>/lab/ssh_debug.log'
cli 'grep -E "Authenticating to|Offering GSSAPI|kex: algorithm|Authentications that|Next authentication|Authentication succeeded|Authenticated to" /lab/ssh_debug.log'
cli 'klist'
# to samo bez wymiany kluczy GSSAPI — czyste uwierzytelnienie gssapi-with-mic
cli 'ssh -v -o BatchMode=yes -o GSSAPIKeyExchange=no student@kerberos.uws.edu.pl id 2>&1 | grep -E "kex: algorithm|Next authentication|Authenticated to|^uid="'
srv 'grep -E "ISSUE" /var/log/krb5kdc.log | tail -2'
srv 'grep -E "Accepted|Authorized" /var/log/sshd.log'
# kontenery dzielą zegar jądra z serwerem, więc tu wystarczy pokazać, że ntpd odpytuje serwery czasu
cli 'ntpq -pn 2>/dev/null | sed -n "1,10p"; date'
cli 'kdestroy && klist; ssh -o BatchMode=yes student@kerberos.uws.edu.pl hostname'

# artefakty dla prowadzącego: baza KDC, stash, keytab
mkdir -p server/artefakty
for f in /var/lib/krb5kdc /etc/krb5kdc /etc/krb5.keytab; do
    docker compose cp "kerberos:$f" server/artefakty/ >/dev/null
done
echo; echo "Gotowe. Log: $LOG"
