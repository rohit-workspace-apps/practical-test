const express = require("express")
const mysql = require("mysql2")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const nodemailer = require("nodemailer")
const cors = require("cors")
const dotenv = require("dotenv")

dotenv.config()

const app = express()
app.use(cors())
app.use(express.json())

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "myapp",
})

db.connect((err) => {
  if (err) throw err
  console.log("MySQL Connected!")
})

app.post("/register/customer", async (req, res) => {
  const { first_name, last_name, email, password } = req.body
  const hashedPassword = await bcrypt.hash(password, 10)

  db.query(
    "INSERT INTO users (first_name, last_name, email, password, role) VALUES (?, ?, ?, ?, ?)",
    [first_name, last_name, email, hashedPassword, "customer"],
    (err) => {
      if (err) return res.status(400).json({ error: err.message })

      // Send verification email (placeholder logic)
      // Add logic to send a verification email here

      res.status(201).json({ message: "Customer registered successfully!" })
    }
  )
})

app.post("/register/admin", async (req, res) => {
  const { first_name, last_name, email, password } = req.body
  const hashedPassword = await bcrypt.hash(password, 10)

  db.query(
    "INSERT INTO users (first_name, last_name, email, password, role) VALUES (?, ?, ?, ?, ?)",
    [first_name, last_name, email, hashedPassword, "admin"],
    (err) => {
      if (err) return res.status(400).json({ error: err.message })

      res.status(201).json({ message: "Admin registered successfully!" })
    }
  )
})

app.post("/login/admin", async (req, res) => {
  const { email, password } = req.body

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err || results.length === 0)
        return res.status(400).json({ error: "User not found" })

      const user = results[0]
      if (user.role !== "admin") {
        return res
          .status(403)
          .json({ error: "You are not allowed to login from here" })
      }

      const isMatch = await bcrypt.compare(password, user.password)
      if (!isMatch)
        return res.status(401).json({ error: "Invalid credentials" })

      // Create JWT Token (optional)
      const token = jwt.sign(
        { id: user.id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      )
      res.json({ token })
    }
  )
})

app.listen(5000, () => {
  console.log("Server running on http://localhost:5000")
})
