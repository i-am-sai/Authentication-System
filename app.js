//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const md5 = require("md5");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findorCreate = require("mongoose-findorcreate");
const bcrypt = require("bcrypt");
const encrypt = require("mongoose-encryption");

const saltRounds = 10;
const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findorCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, { id: user.id, username: user.username, name: user.name });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3300/auth/google/Authentication-System",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"                  // future proofing
},
  function (accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {               // pseudo code
      return cb(err, user);
    });
  }
));

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/registration-success", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("registration-success"); // Render the registration success page
  } else {
    res.redirect("/login"); // Redirect to the login page if not authenticated
  }
});

app.post("/register", function (req, res) {
  User.register({ username: req.body.username }, req.body.password, function (err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/registration-success"); // Redirect to the registration success page
      });
    }
  });
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/Authentication-System",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    if (req.user) {
      res.redirect("/secrets"); // Redirect to the registration success page
    } else {
      res.redirect("/login"); // Redirect to the login page if authentication fails
    }
  }
);

app.get("/secrets", function (req, res) {
  if (req.isAuthenticated()) {
    User.find({ "secret": { $ne: null } })
      .then(function (foundUsers) {
        res.render("secrets", { usersWithSecrets: foundUsers });
      })
      .catch(function (err) {
        console.log(err);
        // Handle the error appropriately
      });
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;

  User.findById(req.user.id)
    .then(function (foundUser) {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        return foundUser.save();
      }
    })
    .then(function () {
      res.redirect("/secrets");
    })
    .catch(function (err) {
      console.log(err);
      // Handle the error appropriately
    });
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      console.log(err);
      // Handle any errors that occurred during logout
      res.redirect("/"); // Redirect to home page or an error page
      return;
    }
    res.redirect("/"); // Redirect to the desired page after successful logout
  });
});

app.listen(3300, function () {
  console.log("Server is started on port 3300.");
});

