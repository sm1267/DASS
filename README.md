# AuthX v1

AuthX v1 este o demonstratie intentionat vulnerabila a unui mecanism de autentificare, realizata pentru proiectul DASS. Aplicatia acopera inregistrarea, autentificarea, logout-ul si resetarea parolei folosind `Express`, `express-session`, `EJS` si SQLite prin modulul built-in `node:sqlite`.

## Ce include v1

- inregistrare utilizator cu salvare in SQLite
- autentificare cu sesiuni server-side
- logout
- flux de forgot/reset password
- dashboard pentru utilizatorii autentificati

## Vulnerabilitati lasate intentionat in aplicatie

Interfata aplicatiei nu afiseaza direct aceste vulnerabilitati; ele sunt documentate aici pentru proiect si pentru etapa ulterioara de hardening din v2.

- parolele sunt stocate in clar
- politica de parola este slaba
- la register se verifica doar prezenta emailului si a parolei
- login-ul afiseaza mesaje diferite pentru user inexistent fata de parola gresita
- nu exista protectie la brute force sau rate limiting
- tokenurile de resetare sunt predictibile si reutilizabile
- setarile cookie-ului de sesiune sunt incomplete

## Rulare locala

Daca `npm` nu este recunoscut in terminalul curent, deschide un terminal nou mai intai.

```bash
npm install
npm start
```

Deschide `http://localhost:3000`.

## Date

- fisierul SQLite folosit: `data/authx-v1.db`
- aplicatia creeaza automat baza de date la prima rulare
