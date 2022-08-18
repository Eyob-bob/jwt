import express from "express";
const app = express();

import jwt from "jsonwebtoken";
import "dotenv/config";
import bcrypt from "bcrypt";

const users = [];

const posts = [
  {
    username: "Eyob",
    title: "Hello guys",
  },
  {
    username: "Nati",
    title: "Hello bros",
  },
];

let refreshTokens = [];

app.use(express.json());

app.get("/posts", authenticate, (req, res) => {
  res.json(posts.filter((post) => post.username === req.user.name));
});

app.post("/token", (req, res) => {
  const refreshToken = req.body.refreshToken;
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(401);

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.send(403);
    const accessToken = generateAccessToken({ name: user.name });
    return res.json({ accessToken });
  });
});

app.delete("/logout", (req, res) => {
  refreshTokens = refreshTokens.filter(
    (refreshToken) => refreshToken !== req.body.refreshToken
  );
  return res.status(204).send("Successfully deleted refresh token");
});

app.post("/register", (req, res) => {
  const username = req.body.username;
  if (!username) return res.status(404).send("Please Enter Username");
  const password = req.body.password;
  if (!password) return res.status(404).send("Please Enter Password");

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(401);
    users.push({ username, password: hashedPassword });
    console.log(users);
    res.status(200).send("User Successfully registered");
  });
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  if (!username) return res.status(404).send("Please Enter Username");
  const password = req.body.password;
  if (!password) return res.status(404).send("Please Enter Password");

  const loggedUser = users.find((user) => user.username === req.body.username);
  if (!loggedUser) {
    return res.status(404).send("user not found");
  }

  if (!bcrypt.compare(password, loggedUser.password)) {
    return res.status(403).send("password incorrect");
  }

  const user = { name: username };

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  refreshTokens.push(refreshToken);

  return res.json({ accessToken, refreshToken });
});

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15s",
  });
}
function generateRefreshToken(user) {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
}

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.listen(3000, () => {
  console.log("listen at 3000");
});
