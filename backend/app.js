const express = require('express');
// const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');

// importing isProduction and CORS middleware from keys.js
const cors = require('cors');
// importing csurf node module to neable CSRF proctection
const csurf = require('csurf');
const { isProduction } = require('./config/keys');

// const indexRouter = require('./routes/index');
const usersRouter = require('./routes/api/users'); // update the import file path
const tweetsRouter = require('./routes/api/tweets');
const csrfRouter = require('./routes/api/csrf');

const app = express();

app.use(logger('dev')); // log request components (URL/method) to terminal
app.use(express.json()); // parse JSON request body
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
// app.use(express.static(path.join(__dirname, 'public')));

// ADD THIS SECURITY MIDDLEWARE
// Security Middleware
if (!isProduction) {
    // Enable CORS only in development because React will be on the React
    // development server (http://localhost:3000). (In production, the Express 
    // server will serve the React files statically.)
    app.use(cors());
  }

// Set the _csrf token and create req.csrfToken method to generate a hashed
// CSRF token
app.use(
    csurf({
      cookie: {
        secure: isProduction,
        sameSite: isProduction && "Lax",
        httpOnly: true
      }
    })
  );


// Attach Express routers
// app.use('/', indexRouter);
app.use('/api/users', usersRouter);
app.use('/api/tweets', tweetsRouter);
app.use('/api/csrf', csrfRouter);


module.exports = app;
