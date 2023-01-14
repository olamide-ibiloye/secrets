// Stage 1 - Username & password
// Stage 2 - Encryption (mongoose-encryption)
// Stage 3 - Hash Encryption (md5)
// Stage 4 - Bcrypt with salt rounds (bcrypt)
// Stage 5 - Session, Passport (express-session, passport, passport-local, passport-local-mongoose)
// Stage 6 - Authentication with Google & Facebook

require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');


const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// activating mongoose and creating mongodb database
mongoose.set('strictQuery', false);
mongoose.connect("mongodb://localhost:27017/userDB");
// mongoose.connect("mongodb+srv://admin-olamide:Test123@cluster0.ehi2v3y.mongodb.net/blogDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

// userSchema.plugin(encrypt, 
//     { secret: process.env.SECRET, encryptedFields: ['password'] });
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

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
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));


passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));


app.get("/", function (req, res) {
    res.render("home");
});


app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] }));


app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect secrets.
        res.redirect("/secrets");
    });


app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    });


app.route("/login")
    .get(function (req, res) {
        res.render("login");
    })
    // .post(function(req, res) {
    //     const username = req.body.username;
    //     // const password = md5(req.body.password);
    //     const password = req.body.password;

    //     User.findOne({email: username}, function(err, foundUser) {
    //         if (!err) {
    //             if (foundUser) {
    //                 bcrypt.compare(password, foundUser.password, function(err, result) {
    //                     if (result) {
    //                         res.render("secrets");
    //                     } else {
    //                         console.log("Incorrect password!");
    //                     }
    //                 });
    //             }
    //         } else {
    //             console.log(err);
    //         }
    //     })
    // })
    .post(function (req, res) {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        req.login(user, function (err) {
            if (err) {
                console.log(error);
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets");
                });
            }
        })
    })

app.route("/register")
    .get(function (req, res) {
        res.render("register");
    })
    // .post(function(req, res) {

    //     bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //         const newUser = new User({
    //             email: req.body.username,
    //             // email: md5(req.body.password),
    //             password: hash
    //         });
    //         newUser.save(function(err) {
    //             if (!err) {
    //                 res.render("secrets");
    //             } else {
    //                 console.log(err);
    //             }
    //         });
    //     });
    // })
    .post(function (req, res) {
        User.register({ username: req.body.username }, req.body.password, function (err, user) {
            if (err) {
                console.log(err);
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("secrets");
                });
            }
        })
    })


app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {
        User.find({secret: { $ne: null }}, function(err, foundUsers) {
            if (!err) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            } else {
                console.log(err);
            }
        });
    } else {
        res.redirect("/login");
    }
});


app.route("/submit")
    .get(function (req, res) {
        if (req.isAuthenticated()) {
            res.render("submit");
        } else {
            res.redirect("/login");
        }
    })
    .post(function(req, res) {
        const submittedSecret = req.body.secret;
        
        User.findById(req.user.id, function(err, foundUser) {
            if (!err) {
                if (foundUser) {
                    foundUser.secret = submittedSecret;
                    foundUser.save(function() {
                        res.redirect("/secrets");
                    });
                }
            } else {
                console.log(err);
            }
        })
    });


app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
    });
    res.redirect("/");
});



app.listen(3000, function () {
    console.log("Server is running on port 3000");
});