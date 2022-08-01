const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const crypto = require("crypto");

require("dotenv").config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

mongoose.connect(process.env.DB_STRING);
const connection = mongoose.connection;
connection.on("error", console.error.bind(console, "mongo connection error"));

const UserSchema = new mongoose.Schema({
  username: String,
  hash: String,
  salt: String,
});

const UserCollection = mongoose.model("UserCollection", UserSchema);

const sessionStore = MongoStore.create({
  mongoUrl: process.env.DB_STRING,
});

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    store: sessionStore,
    cookie: { maxAge: 1000 * 30 },
  })
);

function validPassword(password, hash, salt) {
  const hashVerify = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");
  return hash === hashVerify;
}

function genPassword(password) {
  const salt = crypto.randomBytes(32).toString("hex");
  const genHash = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");
  return {
    salt: salt,
    hash: genHash,
  };
}

passport.use(
  new LocalStrategy((username, password, cb) => {
    UserCollection.findOne({ username: username })
      .then((user) => {
        if (!user) {
          return cb(null, false);
        }

        const isValid = validPassword(password, user.hash, user.salt);

        if (isValid) {
          return cb(null, user);
        } else {
          return cb(null, false);
        }
      })
      .catch((err) => {
        cb(err);
      });
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser((id, cb) => {
  UserCollection.findById(id, (err, user) => {
    if (err) {
      return cb(err);
    }
    cb(null, user);
  });
});

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res, next) => {
  if (req.isAuthenticated()) {
    res.send(
      `<h1>Home</h1> <a href="/login">Login</a> <a href="/register">Register</a> <a href="/protected-route">Protected Route</a> <a href="/logout">Logout</a>`
    );
  } else {
    res.send(
      `<h1>Home</h1> <a href="/login">Login</a> <a href="/register">Register</a> <a href="/protected-route">Protected Route</a>`
    );
  }
});

app.get("/login", (req, res, next) => {
  const form =
    '<h1>Login Page</h1><form method="POST" action="/login">\
    Enter Username:<br><input type="text" name="username">\
    <br>Enter Password:<br><input type="password" name="password">\
    <br><br><input type="submit" value="Submit"></form>';

  res.send(form);
});

app.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/login-failure",
    successRedirect: "/login-success",
  }),
  (err, req, res, next) => {
    if (err) next(err);
  }
);

app.get("/register", (req, res, next) => {
  const form =
    '<h1>Register Page</h1><form method="POST" action="/register">\
    Enter Username:<br><input type="text" name="username">\
    <br>Enter Password:<br><input type="password" name="password">\
    <br><br><input type="submit" value="Submit"></form>';

  res.send(form);
});

app.post("/register", (req, res, next) => {
  const saltHash = genPassword(req.body.password);

  const salt = saltHash.salt;
  const hash = saltHash.hash;

  const newUser = new UserCollection({
    username: req.body.username,
    hash: hash,
    salt: salt,
  });

  newUser.save().then((user) => {
    console.log(user);
  });

  res.redirect("/login");
});

app.get("/protected-route", (req, res, next) => {
  console.log(req.session);
  if (req.isAuthenticated()) {
    res.send("<h1>You are authenticated</h1>");
  } else {
    res.send("<h1>You are not authenticated");
  }
});

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
  });
  res.redirect("/login");
});


app.get("/login-success", (req, res, next) => {
  console.log(req.session);
  res.send("You successfully logged in");
});

app.get("/login-failure", (req, res, next) => {
  res.send("You entered the wrong password");
})

app.listen(3000);
