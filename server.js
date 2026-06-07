const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs'); // do zapisu ticketów

const app = express();
const PORT = process.env.PORT || 3000;

// Ścieżka do pliku z ticketami
const TICKETS_FILE = path.join(__dirname, 'tickets.json');

// ----- Funkcje pomocnicze do odczytu/zapisu ticketów -----
function loadTickets() {
    try {
        if (fs.existsSync(TICKETS_FILE)) {
            const data = fs.readFileSync(TICKETS_FILE, 'utf8');
            return JSON.parse(data);
        }
    } catch (err) {
        console.error('Błąd odczytu tickets.json:', err);
    }
    return [];
}

function saveTickets(tickets) {
    try {
        fs.writeFileSync(TICKETS_FILE, JSON.stringify(tickets, null, 2));
    } catch (err) {
        console.error('Błąd zapisu tickets.json:', err);
    }
}
// ---------------------------------------------------------

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Block direct access to dashboard.html (must go through /dashboard)
app.use('/dashboard.html', (req, res) => res.status(404).send('Not found'));

// Rate limiting for login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Zbyt wiele prób logowania. Spróbuj ponownie później.'
});

// Session configuration
app.use(session({
    secret: 'SEKRET',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 30 * 60 * 1000
    }
}));

// Demo users
const users = [
    {
        username: 'admin',
        passwordHash: '$2a$10$P5S4iSXkUhz8VgDij00tI.VOhTS4WjZhje5a96lc1N05Nb554Qs.a', // admin123
        role: 'Administrator'
    },
    {
        username: 'agent',
        passwordHash: '$2a$10$XXzSr8uAdU19X.e5U7ok1ONgGq2LrRLJeyXiJZF/l4CxK.XezxAkS', // helpdesk
        role: 'Agent'
    }
];

function requireAuth(req, res, next) {
    if (!req.session.loggedIn) {
        return res.status(401).json({ error: 'Brak autoryzacji' });
    }
    next();
}

// Login endpoint
app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
        console.warn(`Nieudana próba logowania dla użytkownika: ${username}`);
        return res.status(401).send('Nieprawidłowy login lub hasło');
    }
    const passwordValid = await bcrypt.compare(password, user.passwordHash);
    if (!passwordValid) {
        console.warn(`Błędne hasło dla użytkownika: ${username}`);
        return res.status(401).send('Nieprawidłowy login lub hasło');
    }

    req.session.regenerate((err) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Błąd logowania');
        }
        req.session.loggedIn = true;
        req.session.username = user.username;
        req.session.role = user.role;
        console.info(`Użytkownik zalogowany: ${user.username}`);
        res.status(200).send({ message: "ok" });
    });
});

// Protected dashboard route
app.get('/dashboard', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Session info API
app.get('/api/session', requireAuth, (req, res) => {
    res.json({
        loggedIn: true,
        username: req.session.username,
        role: req.session.role
    });
});

// ---------- TICKET ENDPOINTS ----------
// Pobierz wszystkie tickety
app.get('/api/tickets', requireAuth, (req, res) => {
    const tickets = loadTickets();
    // Opcjonalnie: sortuj od najnowszych
    tickets.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json(tickets);
});

// Utwórz nowy ticket
app.post('/api/tickets', requireAuth, (req, res) => {
    const { title, description, priority } = req.body;
    if (!title || !description || !priority) {
        return res.status(400).json({ error: 'Wszystkie pola są wymagane: tytuł, opis, priorytet' });
    }
    const tickets = loadTickets();
    const newTicket = {
        id: Date.now(), // proste ID
        title,
        description,
        priority,      // np. 'Low', 'Medium', 'High'
        status: 'open',
        createdBy: req.session.username,
        createdAt: new Date().toISOString()
    };
    tickets.push(newTicket);
    saveTickets(tickets);
    res.status(201).json(newTicket);
});

// Zmień status ticketa (np. na 'closed')
app.patch('/api/tickets/:id/status', requireAuth, (req, res) => {
    const { status } = req.body;
    if (!status || !['open', 'closed'].includes(status)) {
        return res.status(400).json({ error: 'Nieprawidłowy status. Dozwolone: open, closed' });
    }
    const tickets = loadTickets();
    const ticketId = parseInt(req.params.id);
    const ticket = tickets.find(t => t.id === ticketId);
    if (!ticket) {
        return res.status(404).json({ error: 'Ticket nie istnieje' });
    }
    ticket.status = status;
    saveTickets(tickets);
    res.json(ticket);
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Błąd wylogowania');
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
});

app.listen(PORT, () => {
    console.log(`Serwer działa na porcie ${PORT}`);
});