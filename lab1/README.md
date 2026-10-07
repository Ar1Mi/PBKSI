# PBKSI — Laboratorium 1

**Konstrukcja urzędów certyfikacji oraz zarządzanie certyfikatami**

Artur Gubanovich, 7.10.2026
Środowisko: macOS, OpenSSL 3.6.2

Kilka słów na początek:

- Nie ruszałem systemowego `openssl.cnf`. Własną konfigurację trzymam w katalogu laboratorium ([openssl.cnf](openssl.cnf)) i wskazuję ją zmienną `export OPENSSL_CONF="$PWD/openssl.cnf"`.
- Hasło do kluczy i do pliku PKCS #12 to `uwsii`. Podaję je opcjami `-passin` / `-passout`, żeby nie wpisywać go za każdym razem.
- Pełny wynik wszystkich poleceń jest w pliku [wynik.log](wynik.log) — tutaj pokazuję tylko to, co istotne.

## Zadanie 1. Podstawowe funkcje OpenSSL

**a) Wersja**

```console
$ openssl version -a
OpenSSL 3.6.2 7 Apr 2026 (Library: OpenSSL 3.6.2 7 Apr 2026)
built on: Tue Apr  7 12:17:57 2026 UTC
platform: darwin64-arm64-cc
OPENSSLDIR: "/opt/homebrew/etc/openssl@3"
```

**b) Skróty MD5 i SHA-1**

```console
$ printf '%s' 'Artur Gubanovich' | openssl md5 > moje_dane.md5
$ printf '%s' 'Artur Gubanovich' | openssl sha1 > moje_dane.sha
$ cat moje_dane.md5 moje_dane.sha
MD5(stdin)= a8c158a30aa5a3678e0da7cb62ba1d85
SHA1(stdin)= 5d2b817aab6032c0ff1d71473fe4436fc45f46ed
```

Użyłem `printf` zamiast `echo`, żeby do skrótu nie trafił znak nowej linii.

**c) Losowy klucz i szyfrowanie**

2048 bitów to 256 bajtów, czyli 512 znaków w zapisie HEX.

```console
$ openssl rand -hex -out dane.key 256
$ printf '%s\n' 'Artur Gubanovich' > tekst.in
$ openssl enc -aes-256-cbc -a -salt -pbkdf2 -in tekst.in -out tekst.out -pass file:dane.key
$ cat tekst.out
U2FsdGVkX1+zFK1TyiSH1GxCGoxE49cLilfbeH1Y7mErIhdafo+PMhvNA6m4tfM9
```

Zawartość `dane.key` służy jako hasło, z którego razem z solą wyprowadzany jest klucz AES. Dodałem opcję `-pbkdf2`, bo bez niej OpenSSL 3 wyświetla ostrzeżenie o przestarzałym sposobie wyprowadzania klucza. Sól widać w wyniku: początek `U2FsdGVkX1` to zakodowane w Base64 `Salted__`.

**d) Deszyfrowanie**

```console
$ openssl enc -aes-256-cbc -d -a -pbkdf2 -in tekst.out -out tekst.decrypt -pass file:dane.key
$ cat tekst.decrypt
Artur Gubanovich
$ cmp tekst.in tekst.decrypt && echo 'pliki identyczne'
pliki identyczne
```

Tak, dane rozszyfrowały się poprawnie — `tekst.decrypt` jest identyczny z `tekst.in`.

## Zadanie 2. Konfiguracja

Cały plik: [openssl.cnf](openssl.cnf). To, czego wymagało zadanie:

| | Wymaganie | Ustawienie |
|---|---|---|
| a | domyślne CA | `default_ca = moje_ca` |
| b | bieżący katalog | `dir = .` |
| b | ważność 100 dni, CRL co 20 dni | `default_days = 100`, `default_crl_days = 20` |
| c | kraj i województwo muszą pasować | `countryName = match`, `stateOrProvinceName = match` |
| c | nazwa i e-mail wymagane | `commonName = supplied`, `emailAddress = supplied` |
| c | pozostałe pola opcjonalne | `localityName`, `organizationName`, `organizationalUnitName = optional` |
| c | hasło min. 6 znaków | `challengePassword_min = 6` |
| c | wartości domyślne | `countryName_default = PL`, `stateOrProvinceName_default = mazowieckie` |
| d | komentarz | `nsComment = "testowy certyfikat"` |
| e | użytkownik nie wystawia certyfikatów | `basicConstraints = CA:FALSE` |

Że to faktycznie działa, widać w kolejnych zadaniach.

## Zadanie 3. Autocertyfikat CA

**a) Katalogi i pliki**

W instrukcji jest katalog `crt` — uznałem to za literówkę i utworzyłem `crl`, bo tam trafiają listy CRL z zadania 5.

```console
$ mkdir certs crl newcerts private
$ touch index.txt
$ echo 01 > serial
$ echo 01 > crlnumber
```

**b) Klucz prywatny CA**

```console
$ openssl genrsa -out private/cakey.pem 4096
$ openssl rsa -in private/cakey.pem -out private/cakey.pem -outform PEM -des3 -passout pass:uwsii
writing RSA key
$ head -n 1 private/cakey.pem
-----BEGIN ENCRYPTED PRIVATE KEY-----
$ openssl rsa -in private/cakey.pem -passin pass:uwsii -noout -text | head -n 1
Private-Key: (4096 bit, 2 primes)
```

**c) Autocertyfikat na dwa lata**

```console
$ openssl req -new -x509 -days 730 -key private/cakey.pem -passin pass:uwsii -out cacert.pem \
    -subj '/C=PL/ST=mazowieckie/L=Siedlce/O=Uniwersytet w Siedlcach/OU=Instytut Informatyki/CN=Moje CA/emailAddress=artur.gubanovich.2@gmail.com'
$ openssl x509 -in cacert.pem -noout -dates -ext basicConstraints
notBefore=Oct  7 16:50:31 2026 GMT
notAfter=Oct  6 16:50:31 2028 GMT
X509v3 Basic Constraints: critical
    CA:TRUE
```

## Zadanie 4. Certyfikat użytkownika

**a) Klucz i zgłoszenie**

Przy okazji sprawdziłem regułę z zadania 2c. Z hasłem `uwsii` (5 znaków) zgłoszenie nie powstaje:

```console
Podaj haslo []:String too short, must be at least 6 bytes long
Podaj haslo []:Error making certificate request
```

Dlatego jako hasło zgłoszenia podałem `uwsii2026`. Kraj i województwo zostawiłem puste, więc weszły wartości domyślne.

```console
$ openssl req -new -keyout newkey01.pem -out moje_req01.req -passout pass:uwsii
Kod kraju (podaj 2 litery) [PL]:
Nazwa wojewodztwa [mazowieckie]:
Lokalizacja (np. miasto) []:Siedlce
Nazwa organizacji []:Uniwersytet w Siedlcach
Nazwa jednostki []:Instytut Informatyki
Imie i nazwisko wlasciciela []:Artur Gubanovich
Adres skrzynki e-mail []:artur.gubanovich.2@gmail.com
Podaj haslo []:uwsii2026
```

(Odpowiedzi podawałem przez `printf ... |`, dokładne polecenie jest w `wynik.log`.)

**b) Podpisanie przez CA**

```console
$ openssl ca -batch -in moje_req01.req -passin pass:uwsii
Signature ok
Certificate Details:
        Serial Number: 1 (0x1)
        Validity
            Not Before: Oct  7 16:50:41 2026 GMT
            Not After : Jan 15 16:50:41 2027 GMT
        Subject:
            countryName               = PL
            stateOrProvinceName       = mazowieckie
            ...
            commonName                = Artur Gubanovich
            emailAddress              = artur.gubanovich.2@gmail.com
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            Netscape Comment:
                testowy certyfikat
Certificate is to be certified until Jan 15 16:50:41 2027 GMT (100 days)
Database updated
```

Certyfikat trafił do `newcerts/01.pem`. Widać tu ustawienia z zadania 2: 100 dni, `CA:FALSE` i komentarz.

**c) Co się zmieniło w `serial` i `index.txt`**

```console
$ cat serial
02
$ cat index.txt
V	270115165041Z		01	unknown	/C=PL/ST=mazowieckie/L=Siedlce/O=Uniwersytet w Siedlcach/OU=Instytut Informatyki/CN=Artur Gubanovich/emailAddress=artur.gubanovich.2@gmail.com
```

- `serial` zmienił się z `01` na `02` — to numer dla następnego certyfikatu.
- W pustym dotąd `index.txt` pojawił się wiersz: status `V` (ważny), data wygaśnięcia, numer seryjny `01` i dane właściciela.

**d) Drugi certyfikat dla tego samego zgłoszenia**

```console
$ openssl ca -batch -in moje_req01.req -passin pass:uwsii
Signature ok
ERROR:There is already a certificate for /C=PL/ST=mazowieckie/.../CN=Artur Gubanovich/emailAddress=artur.gubanovich.2@gmail.com
The matching entry has the following details
Type          :Valid
Serial Number :01
```

Nie udało się. CA ma już w bazie ważny certyfikat dla tego samego podmiotu i nie wystawi drugiego (`unique_subject = yes`). `serial` i `index.txt` zostały bez zmian.

## Zadanie 5. Listy CRL

**e) Pierwsza lista**

```console
$ openssl ca -gencrl -out crl/lista_1.crl -passin pass:uwsii
$ openssl crl -in crl/lista_1.crl -noout -text
    Last Update: Oct  7 16:50:41 2026 GMT
    Next Update: Oct 27 16:50:41 2026 GMT
No Revoked Certificates.
```

Lista jest pusta, a następna wypada po 20 dniach — tak jak w konfiguracji.

**f) Unieważnienie**

W instrukcji mowa o certyfikacie „z zadania 5”, chodzi oczywiście o ten z zadania 4.

```console
$ openssl ca -revoke newcerts/01.pem -passin pass:uwsii
Revoking Certificate 01.
Database updated
$ cat index.txt
R	270115165041Z	261007165041Z	01	unknown	/C=PL/.../CN=Artur Gubanovich/...
```

Status zmienił się z `V` na `R` i doszła data unieważnienia.

**g) Druga lista z `-crldays` i `-crlhours`**

```console
$ openssl ca -gencrl -crldays 10 -crlhours 12 -out crl/lista_2.crl -passin pass:uwsii
$ openssl crl -in crl/lista_2.crl -noout -text
    Last Update: Oct  7 16:50:41 2026 GMT
    Next Update: Oct 18 04:50:41 2026 GMT
Revoked Certificates:
    Serial Number: 01
        Revocation Date: Oct  7 16:50:41 2026 GMT
```

Kolejna lista CRL ma zostać opublikowana **18 października 2026 o 04:50:41 GMT**, czyli 10 dni i 12 godzin po wystawieniu tej. Opcje z wiersza poleceń zastąpiły domyślne 20 dni.

Dla pewności sprawdziłem jeszcze certyfikat z uwzględnieniem tej listy:

```console
$ openssl verify -crl_check -CAfile cacert.pem -CRLfile crl/lista_2.crl newcerts/01.pem
error 23 at 0 depth lookup: certificate revoked
```

## Zadanie 6. PKCS #12

**a) Eksport**

```console
$ openssl pkcs12 -export -in newcerts/01.pem -inkey newkey01.pem -certfile cacert.pem \
    -name 'Artur Gubanovich' -out 01.p12 -passin pass:uwsii -passout pass:uwsii
```

W pliku `01.p12` jest klucz prywatny, certyfikat użytkownika i certyfikat CA, całość chroniona hasłem.

**b) Import w Firefoksie**

*Ustawienia → Prywatność i bezpieczeństwo → Zarządzaj certyfikatami → karta „Użytkownik” → Importuj… → `01.p12`*, hasło `uwsii`. Po imporcie certyfikat pojawił się na liście — numer seryjny `01`, ważny do 15 stycznia 2027:

![Zaimportowany certyfikat użytkownika](FirefoxUsersCertificate.png)

**c) Import certyfikatu CA**

Na karcie „Organy certyfikacji” wybrałem *Importuj…* i wskazałem `cacert.pem`:

![Wybór pliku cacert.pem](FirefoxCertificate1.png)

Firefox od razu zapytał, do czego ma temu CA ufać:

![Okno z pytaniem o zaufanie do „Moje CA”](FirefoxCertificate2.png)

Czy po imporcie CA certyfikaty przez nie poświadczone są automatycznie zaufane? **Nie.** Sam import tylko dodaje CA do magazynu przeglądarki. O zaufaniu decydują pola widoczne na drugim zrzucie — domyślnie są odznaczone i trzeba je zaznaczyć samemu (można to też zmienić później przez „Edytuj ustawienia zaufania…”). Dopiero wtedy certyfikaty podpisane przez to CA są akceptowane, o ile są ważne i nieunieważnione.
