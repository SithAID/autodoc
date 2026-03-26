const express = require('express');
const path = require('path');
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(__dirname));

// API endpoints
app.post('/api/auth/signup', (req, res) => {
    res.json({ success: true, message: "Signup successful!" });
});

app.post('/api/auth/login', (req, res) => {
    res.json({ success: true, message: "Login successful!" });
});

app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});