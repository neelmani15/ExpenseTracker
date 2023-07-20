//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require('bcrypt');
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const { check, validationResult } = require('express-validator');
const flash = require('connect-flash');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(flash());
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());



mongoose.connect(process.env.URI, { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false });
mongoose.set("useCreateIndex", true);
const expenseSchema = new mongoose.Schema({
  title: {
    type: String,
    // required: true
  },
  amount: {
    type: Number,
    // required: true
  },
  category: {
    type: String,
    // required: true
  },
  date: {
    type: Date,
    default: Date.now
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    // required: true
  }
});

const Expense = mongoose.model('Expense', expenseSchema);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  expenseitems: [expenseSchema]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.use(new LocalStrategy(
//   { usernameField: 'username' },
//   async (username, password, done) => {
//     try {
//       const user = await User.findOne({ username });
//       if (!user) {
//         return done(null, false, { message: 'Invalid username or password' });
//       }
//       const validPassword = await bcrypt.compare(password, user.password);
//       if (!validPassword) {
//         return done(null, false, { message: 'Invalid username or password' });
//       }
//       return done(null, user);
//     } catch (err) {
//       return done(err);
//     }
//   }
// ));

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
  function (accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/expense");
  });

app.get("/login", function (req, res) {
  const formData = req.session.formData || {};
  delete req.session.formData;
  res.render("login", { message: req.flash('error'), formData });
});

app.get("/register", function (req, res) {
  res.render("register", { message: req.flash('error'), formData: req.flash('formData')[0] });
});

app.get("/expense", function (req, res) {
  if (req.isAuthenticated()) {
    const userId = req.user._id;
    // console.log(userId);
    User.find({ _id: userId }, function (err, foundUsers) {
      if (err) {
        console.log(err);
      } else {
        if (foundUsers) {
          const page = parseInt(req.query.page) || 1;
          const limit = parseInt(req.query.limit) || 8;
          const startIndex = (page - 1) * limit;
          const endIndex = startIndex + limit;
          let expenselist = foundUsers[0].expenseitems
          expenselist.sort((a, b) => b.date - a.date);
          const paginatedExpenses = expenselist.slice(startIndex, endIndex);
          const totalPages = Math.ceil(expenselist.length / limit);
          let totalamount = 0;
          expenselist.forEach((expense) => {
            totalamount += expense.amount;
          });
          res.render("expense", {
            message: [],
            total: totalamount,
            userid: userId,
            usersWithexpenses: paginatedExpenses,
            currentpage: page,
            totalpages: totalPages
          });
        }
      }
    });
  }
});
app.get('/:uid/delete/:eid', (req, res) => {
  const userId = req.params.uid
  const expenseId = req.params.eid;
  // console.log(userId);
  // console.log(expenseId);
  User.findById(userId, (err, user) => {
    if (err) {
      console.error(err);
      res.status(500).send('Server error');
    }

    if (!user) {
      // User not found
      res.status(404).send('User not found');
    }
    const expenseIndex = user.expenseitems.findIndex((expense) => expense._id.toString() === expenseId);
    if (expenseIndex === -1) {
      // Expense not found
      res.status(404).send('Expense not found');
    }
    user.expenseitems.splice(expenseIndex, 1);
    user.save((err) => {
      if (err) {
        console.error(err);
        res.status(500).send('Server error');
      }
      res.redirect("/expense");

      // res.render("expense", { userid: userId, usersWithexpenses: user.expenseitems })
      // res.redirect("/expense")
    });
  })
  // if (req.isAuthenticated()) {
  //   const userId = req.user._id;
  //   User.find({ _id: userId }, function (err, foundUser) {
  //     if (err) {
  //       console.log(err);
  //     } else {
  //       if (foundUser) {
  //         const expenselist = foundUser[0].expenseitems

  //         res.render("expense", { usersWithexpenses: expenselist });
  //         // expenselist.forEach((expense)=>{
  //         //   if(expense._id===expenseId){

  //         //   }
  //         // })

  //         console.log(expenselist)
  //       }
  //     }
  //   })
  // const expenseId = req.params.id;
  // Expense.findOneAndDelete({ _id: expenseId }, function (err, foundExpense) {
  //   if (err) {
  //     console.log(err);
  //   }
  //   else {
  //     if (foundExpense) {
  //       console.log(foundExpense);
  //     } else {
  //       console.log("No Expense found")
  //     }
  //   }
  // })
  // }
});
app.get('/:uid/edit/:eid', (req, res) => {
  const userId = req.params.uid;
  const expenseId = req.params.eid;
  User.findById(userId, (err, user) => {
    if (err) {
      console.error(err);
      res.status(500).send('Server error');
    }

    if (!user) {
      // User not found
      res.status(404).send('User not found');
    }
    const expenseIndex = user.expenseitems.findIndex((expense) => expense._id.toString() === expenseId);
    if (expenseIndex === -1) {
      // Expense not found
      res.status(404).send('Expense not found');
    }
    // console.log(user.expenseitems[expenseIndex]);
    res.render("editexpense", { message: [], userid: userId, expense: user.expenseitems[expenseIndex] });

    // res.render("editexpense");
    // res.sendStatus(200);
  });
});
app.get('/viewexpense', (req, res) => {
  if (req.isAuthenticated()) {
    const userId = req.user._id;
    // console.log(userId);
    User.find({ _id: userId }, function (err, foundUsers) {
      if (err) {
        console.log(err);
      } else {
        if (foundUsers) {
          // console.log(foundUsers[0].expenseitems);
          let expenselist = foundUsers[0].expenseitems;
          let totalamount = 0;
          let totalamounthousing = 0;
          let totalamountutilities = 0;
          let totalamounttransport = 0;
          let totalamountgroceries = 0;
          let totalamountfood = 0;
          let totalamountentertainment = 0;
          let totalamounteducation = 0;
          let totalamountother = 0;
          expenselist.forEach((expense) => {
            if (expense.category === 'Housing') {
              totalamounthousing += expense.amount;
            }
            if (expense.category === 'Utilities') {
              totalamountutilities += expense.amount;
            }
            if (expense.category === 'Transportation') {
              totalamounttransport += expense.amount;
            }
            if (expense.category === 'Groceries') {
              totalamountgroceries += expense.amount;
            }
            if (expense.category === 'Food') {
              totalamountfood += expense.amount;
            }
            if (expense.category === 'Entertainment') {
              totalamountentertainment += expense.amount;
            }
            if (expense.category === 'Education') {
              totalamounteducation += expense.amount;
            }
            if (expense.category === 'Others') {
              totalamountother += expense.amount;
            }
            totalamount += expense.amount;
          });
          res.render("viewexpense", {
            totalamount,
            totalamounthousing,
            totalamountutilities,
            totalamounttransport,
            totalamountgroceries,
            totalamountfood,
            totalamountentertainment,
            totalamounteducation,
            totalamountother
          });
        }
      }
    });
  }
})
app.post('/:uid/edit/:eid',
  [
    check('title', 'Title field is required').isAlpha(),
    check('category', 'Category is Required').notEmpty(),
    check('amount', 'Amount must be non negative number').isFloat({ min: 0 })
  ],
  (req, res) => {
    const userId = req.params.uid;
    const expenseId = req.params.eid;
    const updateExpensedata = req.body;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {

      User.findById(userId, (err, user) => {
        if (err) {
          console.error(err);
          res.status(500).send('Server error');
        }

        if (!user) {
          // User not found
          res.status(404).send('User not found');
        }
        const expenseIndex = user.expenseitems.findIndex((expense) => expense._id.toString() === expenseId);
        if (expenseIndex === -1) {
          // Expense not found
          res.status(404).send('Expense not found');
        }
        const errorMessages = errors.array().map(e => e.msg);
        // console.log(user.expenseitems[expenseIndex]);
        res.render("editexpense", { message: errorMessages, userid: userId, expense: user.expenseitems[expenseIndex] });

        // res.render("editexpense");
        // res.sendStatus(200);
      });
      // res.render('editexpense', { message: errorMessages, userid: userId, expense: jhjhhj });
    } else {
      User.findOneAndUpdate({ _id: userId, 'expenseitems._id': expenseId },
        { $set: { 'expenseitems.$': updateExpensedata } },
        { new: true },
        (err, user) => {
          if (err) {
            console.error(err);
            res.status(500).send('Server error');
          }

          if (!user) {
            // User not found or expense not found
            res.status(404).send('User or Expense not found');
          }

          user.save((err, savedUser) => {
            if (err) {
              console.error(err);
              res.status(500).send('Server error');
            }
            res.redirect("/expense");
            // res.send(savedUser);
          })
        })
    }

    // res.redirect("/expense")
    // User.findById(userId, (err, user) => {
    //   if (err) {
    //     console.error(err);
    //     res.status(500).send('Server error');
    //   }

    //   if (!user) {
    //     // User not found
    //     res.status(404).send('User not found');
    //   }
    //   const expenseIndex = user.expenseitems.findIndex((expense) => expense._id.toString() === expenseId);
    //   const expense = user.expenseitems[expenseIndex];
    //   if (expenseIndex === -1) {
    //     res.redirect("/expense")
    //     res.status(404).send('Expense not found');
    //   } else {
    //     expense.title = updateExpensedata.title;
    //     expense.category = updateExpensedata.category;
    //     expense.amount = updateExpensedata.amount;
    //     console.log(expense);
    //     // user.save()
    //     // expense.save();
    //     // user.expenseitems[expenseIndex] = expense;
    //     // res.redirect('/expense')
    //     // res.render("expense", { userid: userId, usersWithexpenses: user.expenseitems });

    //     res.redirect("/expense");
    //   }
    // })
  })
app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit", { message: [] });
  } else {
    res.redirect("/login");
  }
});

app.post("/submit",
  [
    check('title', 'Title field is required').isAlpha(),
    check('category', 'Category is Required').notEmpty(),
    check('amount', 'Amount must be non negative number').isFloat({ min: 0 })
  ],
  function (req, res) {
    // const submittedSecret = req.body.secret;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().map(e => e.msg);
      req.flash('error', errorMessages);
      res.render('submit', { message: errorMessages });
    } else {
      const title = req.body.title;
      const category = req.body.category;
      const amount = req.body.amount;


      //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
      // console.log(req.user.id);

      User.findById(req.user.id, function (err, foundUser) {
        if (err) {
          console.log(err);
        } else {
          if (foundUser) {
            const newExpense = new Expense({
              title, category, amount
            })
            foundUser.expenseitems.push(newExpense);
            foundUser.save(function () {
              // console.log(foundUser);
              res.redirect("/expense");
            });
          }
        }
      });
    }
  });

app.get("/logout", function (req, res) {
  req.logout();
  req.session.user = null;
  res.redirect("/");
});

app.post("/register",
  [
    check('username', 'Email is required or Invalid Email').isEmail(),
    check('password', 'Password must be at least 8 characters').isLength({ min: 8 })
  ],
  async function (req, res) {
    // const errors = validationResult(req);
    // // console.log(errors);
    // let err = {}
    // if (!errors.isEmpty()) {
    //   let errorMessages = errors.array().map(e => e.msg);
    //   res.flash('error', errorMessages);
    //   res.flash('formData', req.body);
    //   res.render('register', { message: errorMessages })
    // }

    // Check if the username or email already exists in the database
    // const existingUser = await User.findOne({ username });

    // if (existingUser) {
    //   req.flash('error', 'Username or email already exists'); // Store the error message in flash
    //   req.flash('formData', req.body); // Store the submitted form data in flash
    //   return res.redirect('/register');
    // }

    //   // Create a new user and save it to the database
    //   const newUser = new User({ username, password });
    //   await newUser.save();

    //   // Redirect to the login page after successful registration
    //   req.flash('success', 'Registration successful');
    //   return res.redirect('/expense');
    // } catch (err) {
    //   console.error(err);
    //   res.status(500).send('Server Error');
    // }
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
      if (err) {
        req.flash('error', 'Email already exists or Invalid user'); // Store the error message in flash
        req.flash('formData', req.body); // Store the submitted form data in flash
        return res.redirect('/register');
        // alert("Username is already exist");
        // res.render("register", { message: ["E-mail already exist"] })
        // console.log(err);
      } else {
        // console.log(user);
        passport.authenticate("local")(req, res, function () {
          req.flash('success_msg', 'You are registerd and can now login');
          res.redirect("/expense");
        });
      }
    });
  });
// app.post('/login', passport.authenticate('local'), (req, res) => {
//   // If the control reaches here, it means the login is successful
//   res.json({ success: true });
// });

app.post("/login",
  [
    check('username', 'Email is required or Invalid Email').isEmail(),
    check('password', 'Password must be at least 8 characters').isLength({ min: 8 })
  ], function (req, res) {

    // const errors = validationResult(req);
    // if (!errors.isEmpty()) {
    //   // console.log(errors);
    //   let errorMessages = errors.array().map(e => e.msg);
    //   req.flash('error', errorMessages);
    //   // res.flash('formData', req.body);
    //   let formData = req.session.formData || '';
    //   req.session.formData = req.body;
    //   // res.redirect('/login');
    //   res.render('login', { message: errorMessages, formData })
    // }
    const user = new User({
      username: req.body.username,
      password: req.body.password
    });
    passport.authenticate('local', function (err, user, info) {
      if (err) {
        console.log(err);
      }
      if (!user) {
        req.flash('error', 'Invalid username or password');
        req.session.formData = req.body;
        // res.flash('formData', req.body);
        return res.redirect('/login');
        // Unauthorized access (invalid username or password)
        // return res.render('login', { message: ['Invalid username or password'] });
      }
      req.logIn(user, function (err) {
        if (err) {
          req.flash('error', 'Invalid username or password');
          // res.flash('formData', req.body);
          console.log(err);
        }
        return res.redirect('/expense');
      });
    })(req, res);
    // req.login(user, function (err) {
    //   if (err) {
    //     // res.render('login', { message: ["Invalid Password or User"] })
    //     console.log(err);
    //   } else {
    //     passport.authenticate("local")(req, res, function () {
    //       res.redirect("/expense");
    //     });
    //   }
    // });

  });







app.listen(3000, function () {
  console.log("Server started on port 3000.");
});
