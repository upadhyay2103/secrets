//jshint esversion:6
import 'dotenv/config';
import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import session from 'express-session';
import passport from 'passport';
import passportLocalMongoose from "passport-local-mongoose";
import { Strategy as GoogleStrategy } from 'passport-google-oauth20'
import findOrCreate from 'mongoose-findorcreate';

const app=express();
const port=3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret:"Our little secret.",
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());

//connection
mongoose.connect("mongodb://127.0.0.1:27017/userDB").then(()=>console.log("mongoDB connected!")).catch(err=>console.log("error generated",err));

//schema
const userSchema=new mongoose.Schema({
    password:{
        type:String
    },
    googleId:{
        type:String,
        unique:true
    },
    username: {
        type: String,
        unique: true  // Make the username field unique
    }
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//model
const User=mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, (err, user)=> {
      return cb(err, user);
    });
  }
));

app.get("/",(req,res)=>{
    res.render("home.ejs");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));


app.get('/auth/google/secrets', 
passport.authenticate('google', { failureRedirect: '/login' }),
function(req, res) {
    // Successful authentication, redirect home.
  res.redirect('/secrets');
});

app.get("/login",(req,res)=>{
    res.render("login.ejs"); 
});

app.get("/register",(req,res)=>{
    res.render("register.ejs");
});

app.get("/secrets",(req,res)=>{
    if(req.isAuthenticated())
    {
        res.render("secrets.ejs");
    }
    else
    {
        res.redirect("/login");
    }
})

app.post("/register", async(req,res)=>{
    User.register({username:req.body.username,active:false},req.body.password,(err,user)=>{
        if(err)
        {
           console.log(err);
           res.redirect("/register");
           console.log(req.body.password);
        }
        else
        {
            passport.authenticate("local")(req,res,()=>{
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login",async(req,res)=>{
    const user=new User({
        username:req.body.username,
        password:req.body.password
    });

    req.login(user,(err)=>{
        if(err)
        {
            console.log(err);
        }
        else
        {
            passport.authenticate("local")(req,res,()=>{
                res.redirect("/secrets");
            })
        }
    });
});

app.get("/logout",(req,res,next)=>{
    req.logout((err)=>{
        if(err){
            return next(err);
        }
        else
        {
            res.redirect("/");
        }
    });
});

app.get("/submit",(req,res)=>{
    res.render("submit.ejs");
});

app.post("/submit",(req,res)=>{
    const rsecret=req.body.secret;
    res.redirect("/");
})

app.listen(port,()=>{
    console.log(`Server running on port ${port}`);
});