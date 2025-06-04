const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const axios = require('axios');
const os = require('os');

const app = express();
const PORT = 3000;
const USERS_FILE = path.join(__dirname, 'users.json');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Redirect extensionful URLs to extensionless (e.g. /dashboard.html -> /dashboard)
app.use((req, res, next) => {
  if (req.method === 'GET') {
    const exts = ['.html', '.htm', '.json', '.js', '.css', '.png', '.jpg', '.jpeg', '.svg', '.ico'];
    for (const ext of exts) {
      if (req.path.endsWith(ext)) {
        const base = req.path.slice(0, -ext.length);
        // Only redirect if the extensionless version does not have an extension and is not root
        if (base && !base.includes('.') && base !== '/') {
          // Check if the file actually exists
          const filePath = path.join(__dirname, req.path);
          if (fs.existsSync(filePath)) {
            return res.redirect(301, base);
          }
        }
      }
    }
  }
  next();
});

// Gelişmiş Clean URL middleware: /dashboard -> /dashboard.html, /apac -> /apac.html, /logo -> /logo.svg, vs.
app.use((req, res, next) => {
  if (
    req.method === 'GET' &&
    !req.path.includes('.') && // no extension
    req.path !== '/' // not root
  ) {
    const exts = ['.html', '.htm', '.json', '.js', '.css', '.png', '.jpg', '.jpeg', '.svg', '.ico'];
    for (const ext of exts) {
      const filePath = path.join(__dirname, req.path + ext);
      if (fs.existsSync(filePath)) {
        return res.sendFile(filePath);
      }
    }
  }
  next();
});

// Simple session management (in-memory)
const sessions = new Map();

// Middleware to check session
const checkSession = (req, res, next) => {
    const sessionId = req.headers['x-session-id'];
    if (!sessionId || !sessions.has(sessionId)) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
    req.user = sessions.get(sessionId);
    next();
};

// Helper function to read users data
const readUsers = () => {
    try {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        // If file doesn't exist or is empty, return an empty array
        return [];
    }
};

// Helper function to write users data
const writeUsers = (users) => {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
};

// Registration endpoint
app.post('/register', (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    const users = readUsers();

    // Check if username already exists
    if (users.find(user => user.username === username)) {
        return res.status(400).json({ message: 'Username already exists.' });
    }

    // Add new user with approved: false (requires admin approval)
    const newUser = {
        username,
        password, // Insecure: store passwords securely in production
        email: email || '', // Optional email
        type: 'user', // Default type is 'user'
        approved: false
    };

    users.push(newUser);
    writeUsers(users);

    res.status(201).json({ message: 'User registered successfully. Awaiting admin approval.' });
});

// Login endpoint
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    const users = readUsers();

    const user = users.find(user => user.username === username && user.password === password);

    if (!user) {
        return res.status(401).json({ message: 'Invalid username or password.' });
    }

    // Check for admin approval if user type is 'user'
    if (user.type === 'user' && !user.approved) {
        return res.status(401).json({ message: 'Your account is awaiting admin approval.' });
    }

    // Create session
    const sessionId = Math.random().toString(36).substring(2);
    sessions.set(sessionId, {
        username: user.username,
        type: user.type
    });

    // Login successful
    res.status(200).json({
        message: 'Login successful!',
        sessionId,
        user: { username: user.username, type: user.type }
    });
});

// Check authentication endpoint
app.get('/check-auth', checkSession, (req, res) => {
    const users = readUsers();
    const user = users.find(u => u.username === req.user.username);
    let projects = [];
    let type = req.user.type;
    let environments = [];
    if (user) {
        if (user.type === 'admin') {
            projects = ['apac', 'tod-tr', 'tod-mena', 'beinconnect'];
            environments = ['TEST', 'REGRESSION', 'PRODUCTION'];
        } else {
            projects = user.projects || [];
            environments = user.environments || [];
        }
        type = user.type;
    }
    res.json({ username: req.user.username, type, projects, environments });
});

// Logout endpoint
app.post('/logout', checkSession, (req, res) => {
    const sessionId = req.headers['x-session-id'];
    sessions.delete(sessionId);
    res.json({ message: 'Logged out successfully' });
});

// Admin endpoints
app.get('/admin/users', checkSession, (req, res) => {
    // Check if user is admin
    if (req.user.type !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }

    const users = readUsers();
    res.status(200).json(users.map(({ password, ...rest }) => rest)); // Exclude passwords
});

app.post('/admin/approve/:username', checkSession, (req, res) => {
    // Check if user is admin
    if (req.user.type !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }

    const { username } = req.params;
    const users = readUsers();
    const userIndex = users.findIndex(user => user.username === username);

    if (userIndex === -1) {
        return res.status(404).json({ message: 'User not found.' });
    }

    if (users[userIndex].type !== 'user') {
         return res.status(400).json({ message: 'Only user type accounts need approval.' });
    }

    if (users[userIndex].approved) {
        return res.status(400).json({ message: 'User is already approved.' });
    }

    users[userIndex].approved = true;
    writeUsers(users);

    res.status(200).json({ message: 'User approved successfully.' });
});

// Endpoint to change user type (admin/user)
app.post('/admin/change-type/:username', checkSession, (req, res) => {
    // Check if user is admin
    if (req.user.type !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }

    const { username } = req.params;
    const { type } = req.body; // Expecting 'admin' or 'user' in the request body

    if (!type || (type !== 'admin' && type !== 'user')) {
        return res.status(400).json({ message: 'Invalid user type specified.' });
    }

    const users = readUsers();
    const userIndex = users.findIndex(user => user.username === username);

    if (userIndex === -1) {
        return res.status(404).json({ message: 'User not found.' });
    }

    // Prevent changing the type of the currently logged-in admin
    if (req.user.username === username && type !== 'admin') {
         return res.status(400).json({ message: 'Cannot demote yourself from admin.' });
    }

    users[userIndex].type = type;
    writeUsers(users);

    res.status(200).json({ message: `User ${username} type changed to ${type}.` });
});

// Endpoint to revoke user login access (set approved to false)
app.post('/admin/revoke-access/:username', checkSession, (req, res) => {
     // Check if user is admin
     if (req.user.type !== 'admin') {
         return res.status(403).json({ message: 'Access denied' });
     }

     const { username } = req.params;
     const users = readUsers();
     const userIndex = users.findIndex(user => user.username === username);

     if (userIndex === -1) {
         return res.status(404).json({ message: 'User not found.' });
     }

    // Prevent revoking access for the currently logged-in admin
    if (req.user.username === username) {
        return res.status(400).json({ message: 'Cannot revoke access for yourself.' });
    }

     users[userIndex].approved = false;
     writeUsers(users);

     res.status(200).json({ message: `Login access revoked for user ${username}.` });
});

// Token endpoint
app.post('/api/token', async (req, res) => {
    try {
        const response = await axios.post('http://172.28.9.123/api/auth', {
            email: "admin@digiturk.com.tr",
            password: "adminPassQA"
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        res.json(response.data);
    } catch (error) {
        console.error('Token error:', error);
        res.status(500).json({ error: 'Failed to get token' });
    }
});

// APAC users endpoint
app.get('/api/apac/users', async (req, res) => {
    try {
        const { environment, userPackage, countryCode } = req.query;
        
        // Convert environment to lowercase for API
        const apiEnvironment = environment.toLowerCase();
        
        // Convert userPackage to lowercase if it's 'none', otherwise keep as is
        const apiUserPackage = userPackage === 'NONE' ? 'none' : userPackage;
        
        const token = req.headers['x-auth-token'];
        
        const response = await axios.get(`http://172.28.9.123/api/apac/apacuser`, {
            params: {
                isValid: true,
                isLocked: false,
                environment: apiEnvironment,
                userPackage: apiUserPackage,
                countryCode: countryCode
            },
            headers: {
                'x-auth-token': token
            }
        });
        
        res.json(response.data);
    } catch (error) {
        console.error('APAC users error:', error);
        res.status(500).json({ error: 'Failed to fetch APAC users' });
    }
});

// Endpoint to mark APAC user as used
app.put('/api/apac/users/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const token = req.headers['x-auth-token'];
        const requestBody = req.body;

        // Ensure the _id is not sent in the body to the external API
        if (requestBody._id) {
            delete requestBody._id;
        }

        // Explicitly set isEmailValid and isLocked as requested
        requestBody.isEmailValid = false;
        requestBody.isLocked = true;

        const response = await axios.put(`http://172.28.9.123/api/apac/apacuser/${userId}`, requestBody, {
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            }
        });

        res.json(response.data);

    } catch (error) {
        console.error('Mark user as used error:', error);
        // Pass the status code from the external API if available, otherwise use 500
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        res.status(statusCode).json({ error: 'Failed to mark APAC user as used' });
    }
});

// Endpoint to get APAC vouchers
app.get('/api/apac/vouchers', async (req, res) => {
    try {
        const { environment, countryCode } = req.query;
        const token = req.headers['x-auth-token'];

        // Basic validation (optional but good practice)
        if (!environment || !countryCode) {
            return res.status(400).json({ error: 'Environment and countryCode are required query parameters.' });
        }

        const response = await axios.get(`http://172.28.9.123/api/apac/vouchers?isUsed=false&environment=${environment}&countryCode=${countryCode}`, {
            headers: {
                'x-auth-token': token
            }
        });

        res.json(response.data);

    } catch (error) {
        console.error('APAC vouchers error:', error);
        // Pass the status code from the external API if available, otherwise use 500
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        res.status(statusCode).json({ error: 'Failed to fetch APAC vouchers' });
    }
});

// Endpoint to mark APAC voucher as used
app.post('/api/apac/vouchers/:id', async (req, res) => {
    try {
        const voucherId = req.params.id;
        const token = req.headers['x-auth-token'];
        const requestBody = req.body;

        // Create new request body with only the required fields
        const newRequestBody = {
            isUsed: true,
            voucherCode: requestBody.voucherCode,
            countryCode: requestBody.countryCode,
            offerType: requestBody.offerType,
            environment: requestBody.environment
        };

        const response = await axios.post(`http://172.28.9.123/api/apac/vouchers/?id=${voucherId}`, newRequestBody, {
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            }
        });

        res.json(response.data);

    } catch (error) {
        console.error('Mark voucher as used error:', error);
        // Pass the status code from the external API if available, otherwise use 500
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        res.status(statusCode).json({ error: 'Failed to mark APAC voucher as used' });
    }
});

// Endpoint to handle DB query for SMS code
app.post('/api/dbquery', async (req, res) => {
    try {
        const { query, environment, project } = req.body;
        const token = req.headers['x-auth-token'];

        // Basic validation
        if (!query || !environment || !project) {
             return res.status(400).json({ error: 'Query, environment, and project are required in the request body.' });
        }

        const response = await axios.post('http://172.28.9.123/api/standalone/dbquery', {
            query: query,
            environment: environment,
            project: project
        }, {
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            }
        });

        res.json(response.data);

    } catch (error) {
        console.error('DB query error:', error);
        // Pass the status code from the external API if available, otherwise use 500
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        res.status(statusCode).json({ error: 'Failed to execute DB query' });
    }
});

// TOD TR Package Users Proxy Endpoint
app.get('/api/tod-tr/package-users', async (req, res) => {
    try {
        // Log incoming query params for debug
        //console.log('Incoming query params:', req.query);
        // Map userPackage values
        const userPackageMap = {
            NONE: 'none',
            NULL: 'null',
            FUN: 'O1A_EGL_OTT',
            SPORT: 'O1A_SPR_OTT',
            EXTRA: 'O1A_SPE_OTT',
            FULL: 'O1A_FULL_OTT'
        };
        // Map environment values
        const environmentMap = {
            TEST: 'test',
            REGRESSION: 'regression',
            PRODUCTION: 'prod'
        };
        // Get params from query
        const { isLocked, isValid, userPackage, environment, userType } = req.query;
        // Map values for API
        const mappedUserPackage = userPackageMap[userPackage] !== undefined ? userPackageMap[userPackage] : userPackage;
        const mappedEnvironment = environmentMap[environment] !== undefined ? environmentMap[environment] : environment;
        // Compose API URL
        const apiUrl = `http://172.28.9.123/api/standalone/standAloneUsers/?isLocked=${isLocked}&isValid=${isValid}&userPackage=${mappedUserPackage}&environment=${mappedEnvironment}&userType=${userType}`;
        // Fetch token as in /api/token
        const tokenResponse = await axios.post('http://172.28.9.123/api/auth', {
            email: "admin@digiturk.com.tr",
            password: "adminPassQA"
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const token = tokenResponse.data.token;
        // LOGGING for debug
        //console.log('API URL:', apiUrl);
        //console.log('Headers:', { 'x-auth-token': token });
        // Make request
        const response = await axios.get(apiUrl, {
            headers: {
                'x-auth-token': token
            }
        });
        //console.log('API response:', response.data);
        res.json(response.data);
    } catch (error) {
        // LOGGING for debug
        if (error.response) {
            console.error('API error status:', error.response.status);
            console.error('API error data:', error.response.data);
        } else {
            console.error('API error:', error.message);
        }
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        let errorMsg = 'Failed to fetch package users';
        if (error.response && error.response.data) {
            if (typeof error.response.data === 'string') {
                errorMsg = error.response.data;
            } else if (error.response.data.error) {
                errorMsg = error.response.data.error;
            } else if (error.response.data.message) {
                errorMsg = error.response.data.message;
            }
        }
        res.status(statusCode).json({ error: errorMsg });
    }
});

// Start the server
function getLocalExternalIp() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

const publicIp = getLocalExternalIp();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on:`);
  console.log(`- Local:   http://localhost:${PORT}`);
  console.log(`- Network: http://${publicIp}:${PORT}`);
});

app.put('/api/tod-tr/package-users/:id', async (req, res) => {
    try {
        const userId = req.params.id;
        // Clone and modify the request body
        const requestBody = { ...req.body };
        delete requestBody._id;
        requestBody.isLocked = true;
        requestBody.isValid = false;
        requestBody.isEmailValid = false;
        // Fetch token as in /api/token
        const tokenResponse = await axios.post('http://172.28.9.123/api/auth', {
            email: "admin@digiturk.com.tr",
            password: "adminPassQA"
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const token = tokenResponse.data.token;
        // Make PUT request to external API
        const response = await axios.put(`http://172.28.9.123/api/standalone/standAloneUsers/${userId}`, requestBody, {
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            }
        });
        res.json(response.data);
    } catch (error) {
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        let errorMsg = 'Failed to mark user as used';
        if (error.response && error.response.data) {
            if (typeof error.response.data === 'string') {
                errorMsg = error.response.data;
            } else if (error.response.data.error) {
                errorMsg = error.response.data.error;
            } else if (error.response.data.message) {
                errorMsg = error.response.data.message;
            }
        }
        res.status(statusCode).json({ error: errorMsg });
    }
});

app.get('/api/tod-tr/vouchers', async (req, res) => {
    try {
        // Map offerType
        const offerTypeMap = {
            'OFFER COUPON': 'offercoupon',
            'FREE TRIAL': 'freetrial'
        };
        const { environment, offerType } = req.query;
        const mappedOfferType = offerTypeMap[offerType] || 'offercoupon';
        // Fetch token as in /api/token
        const tokenResponse = await axios.post('http://172.28.9.123/api/auth', {
            email: "admin@digiturk.com.tr",
            password: "adminPassQA"
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const token = tokenResponse.data.token;
        // Compose API URL (environment is sent as-is)
        const apiUrl = `http://172.28.9.123/api/apac/vouchers?isUsed=false&environment=${environment}&countryCode=TR&offerType=${mappedOfferType}`;
        // Make request
        const response = await axios.get(apiUrl, {
            headers: {
                'x-auth-token': token
            }
        });
        res.json(response.data);
    } catch (error) {
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        let errorMsg = 'Failed to fetch vouchers';
        if (error.response && error.response.data) {
            if (typeof error.response.data === 'string') {
                errorMsg = error.response.data;
            } else if (error.response.data.error) {
                errorMsg = error.response.data.error;
            } else if (error.response.data.message) {
                errorMsg = error.response.data.message;
            }
        }
        res.status(statusCode).json({ error: errorMsg });
    }
});

app.post('/api/tod-tr/vouchers/:id', async (req, res) => {
    try {
        const voucherId = req.params.id;
        // Clone and modify the request body
        const requestBody = { ...req.body };
        delete requestBody._id;
        requestBody.isUsed = true;
        // Fetch token as in /api/token
        const tokenResponse = await axios.post('http://172.28.9.123/api/auth', {
            email: "admin@digiturk.com.tr",
            password: "adminPassQA"
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const token = tokenResponse.data.token;
        // Make POST request to external API
        const response = await axios.post(`http://172.28.9.123/api/apac/vouchers/?id=${voucherId}`, requestBody, {
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            }
        });
        res.json(response.data);
    } catch (error) {
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        let errorMsg = 'Failed to mark voucher as used';
        if (error.response && error.response.data) {
            if (typeof error.response.data === 'string') {
                errorMsg = error.response.data;
            } else if (error.response.data.error) {
                errorMsg = error.response.data.error;
            } else if (error.response.data.message) {
                errorMsg = error.response.data.message;
            }
        }
        res.status(statusCode).json({ error: errorMsg });
    }
});

app.post('/api/tod-tr/dbquery', async (req, res) => {
    try {
        const { query, environment, project } = req.body;
        // Fetch token as in /api/token
        const tokenResponse = await axios.post('http://172.28.9.123/api/auth', {
            email: "admin@digiturk.com.tr",
            password: "adminPassQA"
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const token = tokenResponse.data.token;
        // Make request
        const response = await axios.post('http://172.28.9.123/api/standalone/dbquery', {
            query,
            environment,
            project
        }, {
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            }
        });
        res.json(response.data);
    } catch (error) {
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        let errorMsg = 'Failed to execute DB query';
        if (error.response && error.response.data) {
            if (typeof error.response.data === 'string') {
                errorMsg = error.response.data;
            } else if (error.response.data.error) {
                errorMsg = error.response.data.error;
            } else if (error.response.data.message) {
                errorMsg = error.response.data.message;
            }
        }
        res.status(statusCode).json({ error: errorMsg });
    }
});

// BeinConnect DB Query endpoint
app.post('/api/beinconnect/dbquery', async (req, res) => {
    try {
        const { query, environment, project } = req.body;
        // Fetch token as in /api/token
        const tokenResponse = await axios.post('http://172.28.9.123/api/auth', {
            email: "admin@digiturk.com.tr",
            password: "adminPassQA"
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const token = tokenResponse.data.token;
        // Make request
        const response = await axios.post('http://172.28.9.123/api/standalone/dbquery', {
            query,
            environment,
            project
        }, {
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            }
        });
        res.json(response.data);
    } catch (error) {
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        let errorMsg = 'Failed to execute DB query';
        if (error.response && error.response.data) {
            if (typeof error.response.data === 'string') {
                errorMsg = error.response.data;
            } else if (error.response.data.error) {
                errorMsg = error.response.data.error;
            } else if (error.response.data.message) {
                errorMsg = error.response.data.message;
            }
        }
        res.status(statusCode).json({ error: errorMsg });
    }
});

// BeinConnect Package Users endpoint
app.post('/api/beinconnect/package-users', async (req, res) => {
    try {
        const { userPackage, environment, userType, isLocked, isValid } = req.body;
        // Fetch token as in /api/token
        const tokenResponse = await axios.post('http://172.28.9.123/api/auth', {
            email: "admin@digiturk.com.tr",
            password: "adminPassQA"
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const token = tokenResponse.data.token;
        // Make request
        const response = await axios.post('http://172.28.9.123/api/standalone/package-users', {
            userPackage,
            environment,
            userType,
            isLocked,
            isValid
        }, {
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            }
        });
        res.json(response.data);
    } catch (error) {
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        let errorMsg = 'Failed to fetch package users';
        if (error.response && error.response.data) {
            if (typeof error.response.data === 'string') {
                errorMsg = error.response.data;
            } else if (error.response.data.error) {
                errorMsg = error.response.data.error;
            } else if (error.response.data.message) {
                errorMsg = error.response.data.message;
            }
        }
        res.status(statusCode).json({ error: errorMsg });
    }
});

// BeinConnect Package Users Mark Used endpoint
app.put('/api/beinconnect/package-users/mark-used', async (req, res) => {
    try {
        const { userPackage, environment, userType, isLocked, isValid } = req.body;
        // Fetch token as in /api/token
        const tokenResponse = await axios.post('http://172.28.9.123/api/auth', {
            email: "admin@digiturk.com.tr",
            password: "adminPassQA"
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const token = tokenResponse.data.token;
        // Make request
        const response = await axios.put('http://172.28.9.123/api/standalone/package-users/mark-used', {
            userPackage,
            environment,
            userType,
            isLocked,
            isValid
        }, {
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            }
        });
        res.json(response.data);
    } catch (error) {
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        let errorMsg = 'Failed to mark package user as used';
        if (error.response && error.response.data) {
            if (typeof error.response.data === 'string') {
                errorMsg = error.response.data;
            } else if (error.response.data.error) {
                errorMsg = error.response.data.error;
            } else if (error.response.data.message) {
                errorMsg = error.response.data.message;
            }
        }
        res.status(statusCode).json({ error: errorMsg });
    }
});

// BeinConnect Vouchers endpoint
app.post('/api/beinconnect/vouchers', async (req, res) => {
    try {
        const { environment, offerType, countryCode } = req.body;
        // Fetch token as in /api/token
        const tokenResponse = await axios.post('http://172.28.9.123/api/auth', {
            email: "admin@digiturk.com.tr",
            password: "adminPassQA"
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const token = tokenResponse.data.token;
        // Make request
        const response = await axios.post('http://172.28.9.123/api/standalone/vouchers', {
            environment,
            offerType,
            countryCode
        }, {
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            }
        });
        res.json(response.data);
    } catch (error) {
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        let errorMsg = 'Failed to fetch vouchers';
        if (error.response && error.response.data) {
            if (typeof error.response.data === 'string') {
                errorMsg = error.response.data;
            } else if (error.response.data.error) {
                errorMsg = error.response.data.error;
            } else if (error.response.data.message) {
                errorMsg = error.response.data.message;
            }
        }
        res.status(statusCode).json({ error: errorMsg });
    }
});

// BeinConnect Vouchers Mark Used endpoint
app.post('/api/beinconnect/vouchers/mark-used', async (req, res) => {
    try {
        const { environment, offerType, countryCode } = req.body;
        // Fetch token as in /api/token
        const tokenResponse = await axios.post('http://172.28.9.123/api/auth', {
            email: "admin@digiturk.com.tr",
            password: "adminPassQA"
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const token = tokenResponse.data.token;
        // Make request
        const response = await axios.post('http://172.28.9.123/api/standalone/vouchers/mark-used', {
            environment,
            offerType,
            countryCode
        }, {
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            }
        });
        res.json(response.data);
    } catch (error) {
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        let errorMsg = 'Failed to mark voucher as used';
        if (error.response && error.response.data) {
            if (typeof error.response.data === 'string') {
                errorMsg = error.response.data;
            } else if (error.response.data.error) {
                errorMsg = error.response.data.error;
            } else if (error.response.data.message) {
                errorMsg = error.response.data.message;
            }
        }
        res.status(statusCode).json({ error: errorMsg });
    }
});

// BeinConnect Package Users Satellite endpoint
app.post('/api/beinconnect/package-users-satellite', async (req, res) => {
    try {
        const { environment, frekans, userPackage, userType } = req.body;
        // Map environment
        const environmentMap = {
            test: 'test',
            regression: 'regression',
            prod: 'prod',
            production: 'prod'
        };
        const apiEnvironment = environmentMap[environment] || environment;
        // Compose API URL
        const apiUrl = `http://172.28.9.123/api/standalone/standAloneUsers/?isLocked=false&isValid=true&userPackage=${userPackage}&environment=${apiEnvironment}&frekans=${frekans}&userType=${userType}`;
        // Fetch token as in /api/token
        const tokenResponse = await axios.post('http://172.28.9.123/api/auth', {
            email: "admin@digiturk.com.tr",
            password: "adminPassQA"
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const token = tokenResponse.data.token;
        // Make request
        const response = await axios.get(apiUrl, {
            headers: {
                'x-auth-token': token
            }
        });
        res.json(response.data);
    } catch (error) {
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        let errorMsg = 'Failed to fetch BeinConnect package users (satellite)';
        if (error.response && error.response.data) {
            if (typeof error.response.data === 'string') {
                errorMsg = error.response.data;
            } else if (error.response.data.error) {
                errorMsg = error.response.data.error;
            } else if (error.response.data.message) {
                errorMsg = error.response.data.message;
            }
        }
        res.status(statusCode).json({ error: errorMsg });
    }
});

// BeinConnect Package Users Mark Used by ID endpoint
app.put('/api/beinconnect/package-users/mark-used/:id', async (req, res) => {
    try {
        const userId = req.params.id;
        const body = { ...req.body };
        delete body._id;
        body.isLocked = true;
        body.isValid = false;
        // Fetch token as in /api/token
        const tokenResponse = await axios.post('http://172.28.9.123/api/auth', {
            email: "admin@digiturk.com.tr",
            password: "adminPassQA"
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const token = tokenResponse.data.token;
        // Make PUT request to external API
        const response = await axios.put(`http://172.28.9.123/api/standalone/standAloneUsers/${userId}`, body, {
            headers: {
                'Content-Type': 'application/json',
                'x-auth-token': token
            }
        });
        res.json(response.data);
    } catch (error) {
        const statusCode = error.response && error.response.status ? error.response.status : 500;
        let errorMsg = 'Failed to mark user as used';
        if (error.response && error.response.data) {
            if (typeof error.response.data === 'string') {
                errorMsg = error.response.data;
            } else if (error.response.data.error) {
                errorMsg = error.response.data.error;
            } else if (error.response.data.message) {
                errorMsg = error.response.data.message;
            }
        }
        res.status(statusCode).json({ error: errorMsg });
    }
});

// Kullanıcıya proje yetkisi güncelleme (sadece admin)
app.post('/admin/set-projects/:username', checkSession, (req, res) => {
    if (req.user.type !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    const { username } = req.params;
    const { projects } = req.body; // ör: ["apac", "tod-tr"]
    if (!Array.isArray(projects)) {
        return res.status(400).json({ message: 'Projects must be an array.' });
    }
    const users = readUsers();
    const userIndex = users.findIndex(u => u.username === username);
    if (userIndex === -1) {
        return res.status(404).json({ message: 'User not found.' });
    }
    users[userIndex].projects = projects;
    writeUsers(users);
    res.json({ message: 'Projects updated.' });
});

// Kullanıcıya environment yetkisi güncelleme (sadece admin)
app.post('/admin/set-environments/:username', checkSession, (req, res) => {
    if (req.user.type !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    const { username } = req.params;
    const { environments } = req.body; // ör: ["TEST", "REGRESSION"]
    if (!Array.isArray(environments)) {
        return res.status(400).json({ message: 'Environments must be an array.' });
    }
    const users = readUsers();
    const userIndex = users.findIndex(u => u.username === username);
    if (userIndex === -1) {
        return res.status(404).json({ message: 'User not found.' });
    }
    users[userIndex].environments = environments;
    writeUsers(users);
    res.json({ message: 'Environments updated.' });
}); 