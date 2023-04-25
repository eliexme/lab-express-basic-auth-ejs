const router = require("express").Router();
const User = require('../models/User.model')
const bcryptjs = require('bcryptjs')
const saltRounds = 13
const pwdRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$/

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

//GET for register
router.get("/register", (req, res, next) => {
  res.render("auth/register");
});

//POST for register

router.post("/register", async(req, res, next) => {
  try{
    const potentialUser = await User.findOne({username: req.body.username})
    if(!potentialUser){//meaning is a new user
      if(pwdRegex.test(req.body.password)) {
         //encrypt password
         const salt = bcryptjs.genSaltSync(saltRounds)
         const passwordHash = bcryptjs.hashSync(req.body.password, salt)
         //create the user
         const newUser = await User.create({username: req.body.username, passwordHash: passwordHash})
         res.redirect('/auth/login')
      }else{
        res.render('auth/register', {errorMessage: 'Password is not strong enough', data:{username: req.body.username}})
      }
    }else{
      res.render('auth/register', {errorMessage: 'Username already in use', data:{username: req.body.username}})
    }



  }
  catch(err){console.log(err)}
  
});

//GET for loggin
router.get("/login", (req, res, next) => {
  res.render("auth/login");
});

//POST for loggin
router.post("/login", async(req, res, next) => {
  const loginUser = await User.findOne({username:req.body.username})
  if(!!loginUser){//meaning if the user exists
    if(bcryptjs.compareSync(req.body.password, loginUser.passwordHash)){//if password is correct
      res.render('profile', {loginUser})
      
    }else{//if password is wrong
      res.render('auth/login', {errorMessage: 'Password not correct'})
    }

  }else{
    res.render('auth/login', {errorMessage: 'Username does not exist', data:{username: req.body.username}})
  }
 
});


module.exports = router;
