const express = require("express");
const userRouter = require("./routers/user");
const auth = require("../src/middleware/auth");
const parser = require("body-parser");
const User = require("../src/models/User");
const path = require("path");
const multer = require("multer");
//cookie-parser allows to parse cookies on incoming http requests
const cookieParser = require("cookie-parser");
// const csrf = require('csurf')
const upload = multer();
const port = process.env.PORT;
const app = express();

require("./db/db");

app.use(express.json());
app.use(parser.json());
app.use(parser.urlencoded({ extended: true }));
app.use(cookieParser());
// app.use(csrf({ cookie: true }))

app.get("/", function (req, res) {
  res.sendFile(path.join(__dirname + "/templates/index.html"));
});

app.post("/users", async (req, res) => {
  //create new user
  try {
    const user = new User(req.body);
    await user.save();
    const token = await user.generateAuthToken();
    res.cookie("access_token_cookie", token.accessToken, {
      httpOnly: true,
      secure: true,
    });
    res.cookie("refresh_token_cookie", token.refreshToken, {
      httpOnly: true,
      secure: true,
    });
    res.sendFile(path.join(__dirname + "/templates/signed_up.html"));
  } catch (error) {
    res.json(error);
  }
});

app.post("/users/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findByCredentials(email, password);
    if (!user) {
      return res
        .status(401)
        .send({ error: "Login failed, check authentication credentials" });
    }
    const token = await user.generateAuthToken();
    res.cookie("access_token", token.accessToken, { httpOnly: true });
    res.cookie("refresh_token", token.refreshToken, { httpOnly: true });
    res.redirect("/users/me");
  } catch (error) {
    res.status(400).json(error);
  }
});

app.get("/users/me/reauthenticate", async (req, res) => {
  const refreshToken = req.cookies.refresh_token;
  if (req.user && req.user.refreshTokens.includes(refreshToken)) {
    await req.user.generateAuthToken();
    res.sendFile(path.join(__dirname + "/templates/logged_in.html"))
  } else {
    res.sendFile(path.join(__dirname + "/templates/sign_in.html"))
  }
});

//pass middleware in before method so that it is run before executing rest of function
app.get("/users/me", auth, async (req, res) => {
  res.sendFile(path.join(__dirname + "/templates/logged_in.html"))
});

app.post("/users/me/logout", auth, async (req, res) => {
  try {
    req.user.tokens = req.user.tokens.filter((token) => {
      return token.token != req.token;
    });
    await req.user.save();
    res.json();
  } catch (error) {
    res.status(500).json(error);
  }
});

app.post("/users/me/logoutall", auth, async (req, res) => {
  try {
    req.user.tokens.splice(0, req.user.tokens.length);
    await req.user.save();
    res.send();
  } catch (error) {
    res.status(500).json(error);
  }
});

app.get("/users", function (req, res) {
  res.sendFile(path.join(__dirname + "/templates/sign_up.html"));
});

//currently struggling with how to validate the csrf token against the user submitted form. probably making a mistake with
//adding the token to the form but not entirely sure how to go about it. done a lot of reading on the internet but still
//getting an invalid csrf token error.
app.get("/users/login", function (req, res) {
  // res.cookie('CSRF-TOKEN', req.csrfToken())
  res.sendFile(path.join(__dirname + "/templates/sign_in.html"));
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
