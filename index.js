const express = require('express');
const bodyParser = require('body-parser');
const path = require("path");
const connection = require('./db/db');
const multer = require('multer');
const upload = multer();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

// Middleware to parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));

app.use(upload.any());

// Define routes
const userApiRoutes = require('./routes/api/userRoutes');

app.use('/api/', userApiRoutes);

// Serve static files from the "assets" folder
app.use('/assets', express.static(path.join(__dirname, 'assets')));

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});