# AuthX v2

AuthX v2 este versiunea securizata a aplicatiei pentru proiectul DASS. Aplicatia foloseste `Express`, `express-session`, `EJS` si `SQLite` prin modulul built-in `node:sqlite`.

## Ce include v2

- inregistrare utilizator cu validare backend si politica de parola
- stocare sigura a parolelor cu `scrypt`
- autentificare cu mesaj generic pentru credeniale invalide
- protectie la brute force prin rate limiting si blocare temporara
- sesiuni securizate, regenerate dupa login
- logout cu invalidarea sesiunii
- resetare parola cu token aleator, expirare scurta si invalidare dupa folosire
- tichete asociate utilizatorilor
- jurnal de activitate in `audit_logs`

## Rulare locala

Daca `npm` nu este recunoscut in terminalul curent, deschide un terminal nou sau foloseste `npm.cmd`.

```bash
npm install
npm start
```

Deschide `http://localhost:3000`.

Optional, pentru o configuratie stabila a sesiunilor intre restarturi, seteaza `SESSION_SECRET` inainte sa pornesti serverul.


