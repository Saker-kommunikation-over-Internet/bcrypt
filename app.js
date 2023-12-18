import bodyParser from "body-parser";
import express from "express";
import { createClient } from "redis";
import session from "express-session";
import RedisStore from "connect-redis";
import { compareSync, hashSync } from "bcrypt";

const app = express();
//Ansluter till Redis
const redisClient = createClient();
redisClient.connect();

// Låter oss hantera sessioner via Redis
const redisStore = new RedisStore({ client: redisClient, prefix: "session:" });

//Sätter upp all nödvändig middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  session({
    secret: "myUnsafeSecret",
    saveUninitialized: false,
    resave: false,
    store: redisStore,
  })
);

app.get("/protected", (req, res, next) => {
  if (req.session.isLoggedIn) {
    next();
  } else {
    res.status(401).send("Not permitted.");
  }
});

// En naiv implementation av registrering för att lagra lösenord i klartext.
// En ny användare skapas med det givna lösenordet.
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  await redisClient.set(`user:${username}`, password);
  res.send("Successfully registered!");
});

// En bättre implementation där lösenordet sparas hashat i databasen.
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  //HashSync tar emot 2 argument.
  // 1. Lösenordet som ska hashas.
  // 2. Hur många omgångar det ska saltas. Mer salt = långsammare och säkrare
  const hashedPassword = hashSync(password, 10);

  //Med detta så lagras det hashade värdet i databasen.
  await redisClient.set(`user:${username}`, hashedPassword);
  res.send("Successfully registered!");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const dbPassword = await redisClient.get(`user:${username}`);
  //CompareSync hashar det första argumentet och kollar om det blir det andra argumentet.
  if (compareSync(password, dbPassword)) {
    req.session.isLoggedIn = true;
    res.redirect("/protected");
  } else {
    res.status(401).send("Invalid credentials.");
  }
});

// Den här ska ligga sist. Då körs alla funktioner i respektive get först.
app.use(express.static("public"));

app.listen(8000);
