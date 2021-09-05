require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const app = express();
const auth = require("./middleware/auth");

app.use(express.json());

module.exports = app;

// importing user context
const User = require("./model/user");

// Register
app.post("/register", async (req, res) => {

    // Our register logic starts here
    try {
      // Get user input
      const { first_name, last_name, email, password } = req.body;
  
      // Validate user input
      if (!(email && password && first_name && last_name)) {
        res.status(400).send("All input is required");
      }
  
      // check if user already exist
      // Validate if user exist in our database
      const oldUser = await User.findOne({ email });
  
      if (oldUser) {
        return res.status(409).send("User Already Exist. Please Login");
      }
  
      //Encrypt user password
      encryptedPassword = await bcrypt.hash(password, 10);
  
      // Create user in our database
      const user = await User.create({
        first_name,
        last_name,
        email: email.toLowerCase(), // sanitize: convert email to lowercase
        password: encryptedPassword,
      });
  
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: "2h",
        }
      );
      // save user token
      user.token = token;
  
      // return new user
      res.status(201).json(user);

      await user.save();
    } catch (err) {
      console.log(err);
    }
    // Our register logic ends here
});

// Login
app.post("/login", async (req, res) => {

    // Our login logic starts here
    try {
      // Get user input
      const { email, password } = req.body;
  
      // Validate user input
      if (!(email && password)) {
        res.status(400).send("All input is required");
      }
      // Validate if user exist in our database
      const user = await User.findOne({ email });
  
      if (user && (await bcrypt.compare(password, user.password))) {
        // Create token
        const token = jwt.sign(
          { user_id: user._id, email },
          process.env.TOKEN_KEY,
          {
            expiresIn: "2h",
          }
        );
  
        // save user token
        user.token = token;
  
        // user
        res.status(200).json(user);

        await user.save();
      }
      res.status(400).send("Invalid Credentials");
    } catch (err) {
      console.log(err);
    }
    // Our login logic ends here
  });

// Change Password
app.post("/changepassword", async (req, res) => {
    // Our change password logic starts here
    try {
        // Get user input
        const { email, oldpassword, newpassword } = req.body;
    
        // Validate user input
        if (!(email && oldpassword && newpassword)) {
          res.status(400).send("All input is required");
        }
        // Validate if user exist in our database
        const user = await User.findOne({ email });
    
        if (user && (await bcrypt.compare(oldpassword, user.password))) {
          // Create token
          if (!user.token) {
            const token = jwt.sign(
                { user_id: user._id, email },
                process.env.TOKEN_KEY,
                {
                expiresIn: "2h",
                }
            );
            // save user token
            user.token = token;        
          }
          newencryptedPassword = await bcrypt.hash(newpassword, 10);
          user.password = newencryptedPassword;
            // user
            res.status(200).json(user);

            // save the user details
            await user.save();
        }
        else {
            res.status(400).send("Invalid Credentials");
        }
      } catch (err) {
        console.log(err);
      }
      // Our change password logic ends here
});

app.get("/welcome", auth, (req, res) => {
  res.status(200).send("Welcome!");
});