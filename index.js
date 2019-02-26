const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');  // 1. added this

const db = require('./database/dbConfig.js');
const Users = require('./users/users-module.js');

const server = express();

const sessionConfig = {
  name: 'monkey',
  secret: 'keep it secret, keep it safe',
  cookie: {
    maxAge: 1000 * 60 * 60, // in ms
    secure: false, // used over https only (change to true for production)
  },
  httpOnly: true, // user cannot access the cookie from javascript using document.cookie
  resave: false, // flag to resave cookie on every request
  saveUninitialized: false // law abiding setting cookies automatically
}

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig));  // 2. added this

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;
  // generate hash from user's password
  const hash = bcrypt.hashSync(user.password, 10);
  user.password = hash;

  // override user.password with hash

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      // check that passwords match
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

const protected = (req, res, next) => {
  if (req.session && req.session.user) {
      next();
  } else {
      res.status(401).json({ message: 'Invalid Credentials' });
  }
}
// const protected = (req, res, next) => {
//   const { username, password } = req.headers

//   if (username && password) {
//     Users.findBy({ username })
//       .first()
//       .then(user => {
//         if (user && bcrypt.compareSync(password, user.password)) {
//           next();
//         } else {
//           res.status(401).json({ message: 'Invalid Credentials' });
//         }
//       })
//       .catch(err => {
//         res.status(500).json({ message: 'Ran into unexpected error' });
//       })
//   } else {
//     res.status(404).json({ message: 'No credentials provided' });
//   }
  
// }

// protect this route, only authenticated users should see it
server.get('/api/users', protected, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});



const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
