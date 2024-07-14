// import express, { request } from "express";
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import env from "dotenv";

const app = express();
const port = 3000;

env.config();

const saltRounds = 10;
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("signup.ejs");
});

app.get("/index.ejs", (req, res) => {
  res.render("index.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/adminlogin", (req, res) => {
  res.render("adminlogin.ejs");
});

//////////////////////////////////////////////// Admin Login
app.post("/adminlogin", (req, res) => {
  const { id, password } = req.body;
  const adminId = "bbmsAdmin";
  const adminPassword = "bbmsMainAdmin";

  if (id === adminId && password === adminPassword) {
    // Admin authentication successful
    req.session.isAdminAuthenticated = true; //here how we implemented  Admin Login
    res.redirect("/AdminHome");
  } else {
    res.redirect("/adminlogin");
  }
});

/////////////////////////////////////////////// Admin Home
app.get("/AdminHome", async (req, res) => {
  if (req.session.isAdminAuthenticated) {
    try {
      const result = await db.query("SELECT * FROM bloodinventory");
      console.log("Fetched blood inventory:", result.rows);

      //////////////////////////////////// Fetch user requests with status 'pending'
      const userRequest = await db.query(
        "SELECT * FROM request WHERE status=$1",
        ["pending"]
      );
      console.log("Fetched user requests:", userRequest.rows);
      res.render("AdminHome.ejs", {
        inventory: result.rows,
        userRequest: userRequest.rows,
      });
      console.log("Rendered AdminHome.ejs successfully");
    } catch (err) {
      console.error("Error fetching data:", err);
      res.send("An error occurred while fetching the inventory.");
    }
  } else {
    res.redirect("/adminlogin");
  }
});

//////////////////////////////////////////////////Donor Request
app.get("/donorreq", async (req, res) => {
  if (req.isAuthenticated()) {
    const id = req.user.id;
    const result = await db.query(
      "SELECT id, name, bloodgroup FROM usersignup WHERE id=$1",
      [id]
    );
    const donorID = result.rows[0];
    const slots = await db.query("SELECT  * FROM donationslots");
    res.render("donorreq.ejs", { donorID: donorID, slotsTiming: slots.rows });
  } else {
    res.redirect("/login");
  }
});

/////////////////////////////////////////////////////////////////////////////////////////// Handling
app.post("/donorRequest", async (req, res) => {
  const { Timeslot, donorid } = req.body;

  let id;
  switch (Timeslot) {
    case "09:00:00":
      id = 1;
      break;
    case "10:30:00":
      id = 2;
      break;
    case "13:00:00":
      id = 3;
      break;
    default:
      id = null;
      break;
  }

  if (id != null) {
    await db.query(
      "INSERT INTO appointment (appointmenttime , fetchedid, bloodid) VALUES($1,$2,$3)",
      [Timeslot, donorid, id]
    );
    res.send("Your Appointment Is Booked");
  } else {
    res.status(400).json({ success: false, message: "Problem In ID" });
  }
});

/////////////////////////////////////////////////////////////////////////////////////////AdminHandleDonor
app.get("/adminHandleDonor", async (req, res) => {
  const result = await db.query("SELECT * FROM donationslots");
  console.log(result.rows);

  const donorrequest = await db.query(
    "SELECT u.id , u.name , u.bloodgroup , u.gender , d.appointmenttime , d.bloodid   FROM usersignup as u INNER JOIN appointment as d on u.id = d.fetchedid ORDER BY d.bloodid ASC"
  );

  const plusdonorreq = await db.query("SELECT ds.id , a.appointmenttime FROM appointment AS a INNER JOIN donationslots AS ds ON a.bloodid = ds.id ORDER BY ds.id ASC");
  res.render("adminHandleDonor.ejs", { slotsTime: result.rows , donordata : donorrequest.rows ,plusdonorreq : plusdonorreq.rows }); 
});

app.post("/edit", async (req, res) => {
  const { updatedItemTitle, updatedItemId } = req.body;
  const result = await db.query(
    "UPDATE donationslots SET availableslots = $1 WHERE id=$2 RETURNING *",
    [updatedItemTitle, updatedItemId]
  );
  console.log("Updated Slots", result.rows[0]);
  res.redirect("/adminHandleDonor");
});

app.post("/add", async (req, res) => {
  const newItem = req.body.newItem;
  const result = await db.query(
    "INSERT INTO donationslots (availableslots) VALUES($1) RETURNING *",
    [newItem]
  );
  console.log("New Added Item", result.rows[0]);
  res.redirect("/adminHandleDonor");
});

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////// Add Blood
app.post("/addblood", async (req, res) => {
  const { bloodgroup, quantity } = req.body;
  try {
    await db.query(
      "UPDATE bloodinventory SET quantity = quantity + $1 WHERE bloodgroup = $2",
      [quantity, bloodgroup]
    );
    res.redirect("/AdminHome");
  } catch (err) {
    console.error("Error adding blood to inventory:", err);
    res.send("An error occurred while adding blood to the inventory.");
  }
});

/////////////////////////////////////////////////////////////////// Grant Request
app.post("/admin/grant/:id/:bloodgroup", async (req, res) => {
  const requestId = req.params.id;
  const bloodgroup = req.params.bloodgroup;
  try {
    const { rows: requestRows } = await db.query(
      "UPDATE request SET status = $1 WHERE id = $2 RETURNING *",
      ["completed", requestId]
    );
    const request = requestRows[0];

    await db.query(
      "UPDATE bloodinventory SET quantity = quantity - $1 WHERE bloodgroup = $2",
      [request.quantity, bloodgroup]
    );
    res.redirect("/AdminHome");
  } catch (err) {
    console.error("Error granting request:", err);
    res.send("An error occurred while granting the request.");
  }
});

///////////////////////////////////////////////////////////////////// Secrets Page
app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT * FROM bloodinventory");
      res.render("secrets.ejs", {
        bloodGroups: result.rows,
        inventory: result.rows,
        id: req.user.id,
      });
    } catch (err) {
      console.error("Error fetching inventory:", err);
      res.send("An error occurred while fetching the inventory.");
    }
  } else {
    res.redirect("/login");
  }
});

////////////////////////////////////////////////////////////////////////// Post Secrets
app.post("/your-form-handler", async (req, res) => {
  const { name, bloodgroup, quantity, donationDate, userid } = req.body;
  try {
    const result = await db.query(
      "INSERT INTO request (bloodgrantto, bloodgroup, quantity, orderdate, status, fetchedid) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
      [name, bloodgroup, quantity, donationDate, "pending", userid]
    );
    const requestId = result.rows[0].id;
    res.redirect(`/print/${requestId}`);
  } catch (err) {
    console.error("Error making request:", err);
  }
});

///////////////////////////////////////////////////////////////////////Download Receipt
app.get("/print/:id", async (req, res) => {
  const requestid = req.params.id;
  try {
    // const result = await db.query("SELECT *  FROM request WHERE id=$1", [
    //   requestid,
    // ]);

    const result = await db.query(
      "SELECT us.id,us.name,us.aadhar,r.id,r.bloodgrantto,r.bloodgroup,r.quantity,r.orderdate,r.status FROM usersignup as us INNER JOIN request as r on us.id = r.fetchedid where us.id = 1"
    );
    console.log(result.rows);
    const request = result.rows;
    if (request) {
      res.render("print.ejs", { request: request });
    } else {
      res.send("Request not found");
    }
  } catch (err) {
    console.log(err);
  }
});

/////////////////////////////////////////////////////////////////////////// Request History
app.get("/history", async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM request WHERE status=$1", [
      "completed",
    ]);
    const completed = result.rows;
    res.render("history", { reqhistory: completed });
    console.log(completed);
  } catch (err) {
    console.error("Error fetching request histories:", err);
    res.send("An error occurred while fetching the request histories.");
  }
});

///////////////////////////////////////////////////////////////////////////// User Login
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/index.ejs",
    failureRedirect: "/login",
  })
);

///////////////////////////////////////////////////////////////////////////// User Signup
app.post("/", async (req, res) => {
  const { name, address, gender, aadhar, bloodgroup, password } = req.body;
  try {
    const checkResult = await db.query(
      "SELECT * FROM usersignup WHERE aadhar = $1",
      [aadhar]
    );

    if (checkResult.rows.length > 0) {
      res.send("You are already a user, try logging in.");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
          res.send(
            "Error during hashing password. Don't worry, the problem will be solved soon!"
          );
        } else {
          const result = await db.query(
            "INSERT INTO usersignup (name, address, gender, aadhar, bloodgroup, password) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
            [name, address, gender, aadhar, bloodgroup, hash]
          );
          const user = result.rows[0];
          console.log("User registered:", user);
          req.login(user, (err) => {
            if (err) {
              console.error("Error logging in:", err);
              return next(err);
            }
            console.log("User logged in successfully");
            return res.redirect("/index.ejs");
          });
        }
      });
    }
  } catch (err) {
    console.error("Registration error:", err);
    res.send(
      "An error occurred during registration. Don't worry, we are working on it."
    );
  }
});

passport.use(
  new LocalStrategy({ usernameField: "aadhar" }, async function verify(
    aadhar,
    password,
    cb
  ) {
    try {
      console.log("Authenticating user:", aadhar);
      const result = await db.query(
        "SELECT * FROM usersignup WHERE aadhar=$1",
        [aadhar]
      );
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedPassword = user.password;
        bcrypt.compare(password, storedPassword, (err, isMatch) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (isMatch) {
              console.log("Password match successful");
              return cb(null, user);
            } else {
              console.log("Incorrect password");
              return cb(null, false, { message: "Incorrect password" });
            }
          }
        });
      } else {
        console.log("User not found");
        return cb(null, false, { message: "User not found" });
      }
    } catch (err) {
      console.error("Authentication error:", err);
      return cb(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  console.log("Serializing user:", user.id);
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM usersignup WHERE id=$1", [id]);
    if (result.rows.length > 0) {
      console.log("Deserializing user:", result.rows[0]); // Debugging log
      cb(null, result.rows[0]);
    } else {
      cb(new Error("User not found"));
    }
  } catch (err) {
    cb(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
