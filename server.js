const express = require('express')
// tokenRouter is the router, authenticateToken is the middelware
const { tokenRouter, authenticateToken } = require('./routes/token')

// Initialises express app
const app = express()
const PORT = 8080

app.listen(PORT, () => {
  console.log(`Express listening on port: ${PORT}`)
})

// ------------------- EXTERNAL ROUTES -------------------
app.use('/token', tokenRouter)

// ------------------- ROUTES -------------------

// Example on how to use middleware to authenticate a user as well as
// gaining access to the user object
app.get('/data', authenticateToken, (req, res) => {
  res.send(`<h2>Welcome ${req.user.email}</h2>`)
})
