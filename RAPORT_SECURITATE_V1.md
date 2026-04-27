# Raport de securitate - AuthX v1

## 1. Context

Acest raport documenteaza vulnerabilitatile identificate in versiunea `v1` a aplicatiei AuthX, in conformitate cu cerintele din PDF-ul proiectului "Break the Login - Atacarea si securizarea autentificarii".

Aplicatia analizata foloseste:

- `Node.js + Express`
- `express-session`
- `SQLite`
- tabelele `users`, `tickets`, `audit_logs`

Scopul versiunii `v1` este sa fie functionala, dar sa pastreze vulnerabilitati reale care pot fi demonstrate prin PoC-uri controlate.

## 2. Rezumat executiv

Vulnerabilitatile prezente in `v1` sunt:

1. `4.1 Password Policy slaba`
2. `4.2 Stocare nesigura a parolelor`
3. `4.3 Lipsa rate limiting / brute force`
4. `4.4 User Enumeration`
5. `4.5 Gestionare nesigura a sesiunilor`
6. `4.6 Resetare parola nesigura`

Pe scurt:

- `v1` respecta modelul vulnerabil cerut in proiect
- aplicatia este functionala si permite demonstratii PoC
- vulnerabilitatile sunt intentionate si trebuie eliminate in `v2`

## 3. Suprafata analizata

Rutele principale analizate:

- `GET /register`
- `POST /register`
- `GET /login`
- `POST /login`
- `POST /logout`
- `GET /forgot-password`
- `POST /forgot-password`
- `GET /reset-password/:token`
- `POST /reset-password/:token`
- `GET /tickets`
- `POST /tickets`
- `GET /dashboard`

Fisiere relevante:

- [src/app.js](/c:/Users/stefa/Desktop/DASS/src/app.js:1)
- [src/db.js](/c:/Users/stefa/Desktop/DASS/src/db.js:1)

## 4. Vulnerabilitati identificate

### 4.1 Password Policy slaba

**Cerința PDF**

- Sunt acceptate parole foarte scurte sau triviale
- Nu exista validare reala a complexitatii la inregistrare

**Situatia in v1**

La inregistrare exista doar validare de baza pentru prezenta campurilor, formatul emailului si lungimi maxime. Nu exista:

- lungime minima a parolei
- cerinta de complexitate
- blocarea parolelor triviale

Cod relevant:

- [src/app.js](/c:/Users/stefa/Desktop/DASS/src/app.js:79)
- [src/app.js](/c:/Users/stefa/Desktop/DASS/src/app.js:143)

**PoC**

Inregistreaza un cont cu parola foarte slaba:

```powershell
curl.exe -i -X POST http://127.0.0.1:3000/register ^
  -d "email=slab@example.com&password=123"
```

Rezultatul asteptat:

- contul este creat cu succes
- aplicatia accepta parola `123`

**Impact**

- conturile pot fi compromise usor prin ghicire
- credential stuffing si brute force devin mult mai eficiente

**Fix necesar in v2**

- lungime minima pentru parola
- reguli minime de complexitate
- eventual blocare pentru parole foarte comune

---

### 4.2 Stocare nesigura a parolelor

**Cerința PDF**

- parole stocate in clar sau cu hash slab

**Situatia in v1**

Parola este salvata direct in coloana `password`, fara hash si fara salt.

Cod relevant:

- [src/db.js](/c:/Users/stefa/Desktop/DASS/src/db.js:16)
- [src/db.js](/c:/Users/stefa/Desktop/DASS/src/db.js:205)

**PoC**

1. Creeaza un utilizator
2. Interogheaza baza de date

Exemplu:

```powershell
@'
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync('data/authx-v1.db');
console.log(db.prepare("SELECT id, email, password FROM users").all());
'@ | node -
```

Rezultatul asteptat:

- parolele apar in clar in baza de date

**Impact**

- compromiterea bazei de date inseamna compromiterea imediata a conturilor
- reutilizarea parolelor pe alte servicii devine critica

**Fix necesar in v2**

- hash modern (`bcrypt`, `argon2` sau `scrypt`)
- niciodata parola in clar in baza de date

---

### 4.3 Brute force / lipsa rate limiting

**Cerința PDF**

- numar nelimitat de incercari la login
- fara blocare de cont

**Situatia in v1**

Ruta `POST /login` nu aplica:

- rate limiting
- cooldown
- blocare temporara a contului

Schema contine campul `locked`, dar logica de autentificare nu il foloseste.

Cod relevant:

- [src/app.js](/c:/Users/stefa/Desktop/DASS/src/app.js:181)
- [src/db.js](/c:/Users/stefa/Desktop/DASS/src/db.js:24)

**PoC**

Repeta mai multe incercari de login pentru acelasi utilizator:

```powershell
curl.exe -i -X POST http://127.0.0.1:3000/login -d "email=test@example.com&password=111"
curl.exe -i -X POST http://127.0.0.1:3000/login -d "email=test@example.com&password=222"
curl.exe -i -X POST http://127.0.0.1:3000/login -d "email=test@example.com&password=333"
```

Rezultatul asteptat:

- toate cererile sunt procesate
- nu exista blocare, delay sau limitare

**Impact**

- parola poate fi ghicita prin incercari repetate
- aplicatia este vulnerabila la atacuri automate simple

**Fix necesar in v2**

- rate limiting pe endpoint-ul de login
- blocare temporara dupa `N` incercari
- utilizarea reala a campului `locked`

---

### 4.4 User Enumeration

**Cerința PDF**

- mesaje diferite pentru user inexistent versus parola gresita

**Situatia in v1**

Login-ul raspunde diferit in cele doua cazuri:

- `Nu exista niciun cont asociat acestui email.`
- `Parola este incorecta.`

Cod relevant:

- [src/app.js](/c:/Users/stefa/Desktop/DASS/src/app.js:186)
- [src/app.js](/c:/Users/stefa/Desktop/DASS/src/app.js:199)

**PoC**

```powershell
curl.exe -i -X POST http://127.0.0.1:3000/login -d "email=inexistent@example.com&password=123"
curl.exe -i -X POST http://127.0.0.1:3000/login -d "email=test@example.com&password=gresita"
```

Rezultatul asteptat:

- primul raspuns indica faptul ca utilizatorul nu exista
- al doilea raspuns indica faptul ca utilizatorul exista, dar parola este gresita

**Impact**

- un atacator poate enumera adresele valide
- atacurile de brute force si phishing devin mai eficiente

**Fix necesar in v2**

- mesaj generic unic, de exemplu `Invalid credentials`
- timp de raspuns uniform

---

### 4.5 Gestionare nesigura a sesiunilor

**Cerința PDF**

- cookie fara `HttpOnly / Secure / SameSite`
- expirare prea lunga
- reutilizarea sesiunii

**Situatia in v1**

Configuratia de sesiune este intentionat slaba:

- `httpOnly: false`
- `secure: false`
- lipseste `sameSite`
- `maxAge` este `7` zile
- sesiunea nu este regenerata dupa login

Cod relevant:

- [src/app.js](/c:/Users/stefa/Desktop/DASS/src/app.js:30)
- [src/app.js](/c:/Users/stefa/Desktop/DASS/src/app.js:213)

**PoC**

Verifica in DevTools sau in Burp cookie-ul `authx.sid` dupa autentificare:

- nu este `HttpOnly`
- nu este `Secure`
- nu are `SameSite`
- are durata lunga

**Impact**

- sesiunea este mai usor de furat sau reutilizat
- expunerea la XSS sau session hijacking este mai mare

**Fix necesar in v2**

- `HttpOnly: true`
- `Secure: true` in HTTPS
- `SameSite`
- expirare mai scurta
- regenerare de sesiune dupa login

---

### 4.6 Resetare parola nesigura

**Cerința PDF**

- token predictibil
- token reutilizabil
- fara expirare

**Situatia in v1**

Tokenul de resetare este generat astfel:

```text
reset-<user.id>
```

El este:

- predictibil
- refolosibil
- fara expirare efectiva
- neinvalidat dupa folosire

Cod relevant:

- [src/app.js](/c:/Users/stefa/Desktop/DASS/src/app.js:333)
- [src/app.js](/c:/Users/stefa/Desktop/DASS/src/app.js:384)
- [src/db.js](/c:/Users/stefa/Desktop/DASS/src/db.js:210)

**PoC**

1. Cere resetare pentru un cont
2. Observa tokenul afisat
3. Acceseaza `/reset-password/reset-1` sau tokenul generat
4. Schimba parola
5. Refoloseste acelasi token din nou

Exemplu:

```powershell
curl.exe -i -X POST http://127.0.0.1:3000/forgot-password -d "email=test@example.com"
curl.exe -i -X POST http://127.0.0.1:3000/reset-password/reset-1 -d "password=nouaparola"
curl.exe -i -X POST http://127.0.0.1:3000/reset-password/reset-1 -d "password=alta_parola"
```

Rezultatul asteptat:

- acelasi token functioneaza de mai multe ori

**Impact**

- un atacator poate anticipa sau reutiliza tokenul
- compromiterea contului devine mult mai usoara

**Fix necesar in v2**

- token random criptografic
- expirare scurta
- token one-time
- invalidare dupa utilizare

## 5. Observatii despre baza de date

Structura minima ceruta este prezenta:

- `users`
- `tickets`
- `audit_logs`

Cod relevant:

- [src/db.js](/c:/Users/stefa/Desktop/DASS/src/db.js:16)
- [src/db.js](/c:/Users/stefa/Desktop/DASS/src/db.js:27)
- [src/db.js](/c:/Users/stefa/Desktop/DASS/src/db.js:39)

Relatii implementate:

- `users -> tickets (1:N)` prin `owner_id`
- `users -> audit_logs (1:N)` prin `user_id`

Nota:

- relatia conceptuala `tickets -> audit_logs` este reprezentata logic prin `resource` si `resource_id`, nu prin foreign key direct

## 6. Ce este deja bine pentru v1

Versiunea `v1` este potrivita pentru etapa vulnerabila a proiectului deoarece:

- aplicatia este functionala
- poate fi rulata local
- vulnerabilitatile cerute exista si pot fi demonstrate
- exista jurnalizare minima in `audit_logs`
- exista tichete asociate utilizatorilor

## 7. Ce mai trebuie facut pentru predare

Din punct de vedere al codului, `v1` este practic gata.

Pentru predare, mai trebuie:

1. capturi de ecran pentru fiecare PoC
2. request / response relevante din `curl`, `Postman` sau `Burp`
3. o sectiune scurta de impact pentru fiecare vulnerabilitate
4. ulterior, implementarea `v2` si partea de re-test

## 8. Concluzie

`AuthX v1` respecta modelul cerut de proiect pentru o versiune vulnerabila si functionala. Vulnerabilitatile principale cerute in PDF sunt prezente si pot fi demonstrate reproductibil. Din acest motiv, versiunea actuala poate fi folosita ca baza pentru:

- mini-pentest
- capturi PoC
- comparatia cu `v2`

Pe scurt:

- `v1` este gata ca implementare vulnerabila
- nu este inca gata de predare fara dovezile practice si documentarea PoC-urilor
