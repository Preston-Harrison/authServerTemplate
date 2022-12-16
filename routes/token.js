/*
  This module exports the token router (tokenRouter) and authentication
  middleware (authenticateToken).

  The way to use this token api from a frontend is by first attempting to login
  with the login route. This will respond a token and refresh token in the body. 
  When making requests to routes that require authentication, add the token in
  the authorization header (Authorization: Bearer TOKEN). The only exception to
  this is when the authorization has expired. When this happens, GET a new token
  from the refresh route. When you do this, you must authorize the request with the 
  refresh token instead of the expired token (Authorization: Bearer REFRESH_TOKEN).
  To stop the refresh token from being used after the user exits the frontend, be 
  sure to DELETE on the logout route, including the refresh token in the body of the 
  request.

  Author: Preston Harrison / prestonharrison.com / 23rd October 2021

  The routes included are:
  POST /create - creates a user with email and password
  POST /login - responds with a token and refresh token given a valid
  username and password
  GET /refresh - with a valid refresh token as authorization, reponds with
  a new authentication token
  DELETE /logout - logs out a user with a specified refresh token in the body

  Sections:
  1. CUSTOM MESSAGES
  2. JWT FUNCTIONS
  3. DATABASE FUNCTIONS
  4. MIDDLEWARE
  5. ROUTES
*/

const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')

// Keep this secret! It allows you, and only you, to generate JWT tokens
const { PRIVATE_KEY, PRIVATE_REFRESH_KEY } = require('../privateKey')

// Initialise router
const tokenRouter = express.Router()

// ------------------- CUSTOM MESSAGES -------------------
const MISSING_EMAIL_OR_PASSWORD = 'You must include an email and password'
const INVALID_PASSWORD = 'The password provided is invalid'
const USER_ALREADY_EXISTS = 'This user already exists'
const USER_DOESNT_EXIST = 'This user does not exist'
const PASSWORD_REQUIREMENTS =
  'The password must be at least 8 characters and must not contain spaces'
const ACCOUNT_CREATED_SUCCESSFULLY = 'The account was created successfully'
const SERVER_CREATION_ERROR =
  'Internal server error. The account could not be created'
const TOKEN_REQUIRED = 'A token is required to access this content'
const INVALID_TOKEN = 'This token is invalid. Please refresh it.'

// ------------------- JWT FUNCTIONS -------------------
// Change this to the expiry time you would like the original token to have
const TOKEN_EXPIRY_TIME = '1m'

/**
 * Returns an authentication token with a given email
 * @param {String} email - the email to be sent in the token
 * @returns {String} a JWT token
 */
function generateJWT (email) {
  return jwt.sign({ email }, PRIVATE_KEY, { expiresIn: TOKEN_EXPIRY_TIME })
}

// Should probably be done with another method in production. This array
// stores refresh tokens which will be removed when the user logs out.
const refreshTokens = new Map()

/**
 * Returns a refresh authentication token with a given email
 * @param {String} email - the email to be sent in the refresh token
 * @returns {String} a refresh JWT token
 */
function generateRefreshJWT (email) {
  return jwt.sign({ email }, PRIVATE_REFRESH_KEY)
}

/**
 * Adds a refresh token to the list of refresh tokens
 * @param {String} token - the token to be added
 */
async function addRefreshToken (token) {
  // This can be replaced by whatever method you are using to store
  // refresh tokens.
  jwt.verify(token, PRIVATE_REFRESH_KEY, (err, user) => {
    refreshTokens.set(user.email, token)
  })
}

/**
 * Removes this refresh token from the list of tokens
 * @param {String} token - the token to be removed
 */
async function removeRefreshToken (token) {
  // Replace this with whatever method works for your database
  jwt.verify(token, PRIVATE_REFRESH_KEY, (err, user) => {
    refreshTokens.delete(user.email)
  })
}

/**
 * Checks if the given refresh token exists in the database
 * @param {String} token
 * @returns {Boolean} true if refresh token exists in the database,
 * false otherwise
 */
async function refreshTokenExists (token) {
  // Replace this with a method to do this in your own database
  for (let value of refreshTokens.values()) {
    if (value === token) {
      return true
    }
  }
  return false
}

// ------------------- DATABASE FUNCTIONS -------------------

// Just for an example backend. This should absolutely be changed for
// production
const users = []

/**
 * Saves a new user to the database. Assumes user does not already exist
 * and email/password combo is valid.
 * @param {String} email - the email of the user to be saved
 * @param {String} password - the hashed password of the user to be saved
 * @returns {Boolean} true if the user was created successfully, false otherwise
 */
async function createUser (email, password) {
  try {
    // implement your own function body, this is simply an example
    // with an array of users in memory
    users.push({
      email,
      password,
      createdAt: new Date().toString()
    })
    // leave return true so that the routes know the insertion was successful
    return true
  } catch (error) {
    console.log(error)
    return false
  }
}

/**
 * Gets a user object with this email. Returns null if no user is found.
 * @param {String} email - the email of the user to be searched for
 * @returns {Object} - a javascript object of the form: {email, password}
 */
async function getUser (email) {
  // implement your own function body, this is simply an example
  // with an array of users in memory
  const user = users.find(user => {
    return user.email === email
  })
  if (user !== undefined) {
    return user
  } else {
    return null
  }
}

// ------------------- MIDDLEWARE -------------------
tokenRouter.use(express.json())

/**
 * Makes sure the user is who they claim they are in their token. Once
 * authenticated, the user is saved in req.user
 * @param {*} req - http request object
 * @param {*} res - http response object
 * @param {*} next - function to be called once middleware is complete
 */
function authenticateToken (req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (token == null) return res.status(401).json({ msg: TOKEN_REQUIRED })

  jwt.verify(token, PRIVATE_KEY, (error, user) => {
    if (error) {
      return res.status(403).json({ msg: INVALID_TOKEN })
    }

    req.user = user
    next()
  })
}

// ------------------- ROUTES -------------------

// Creates an account with an email and password. JSON body must
// include {email, password}
tokenRouter.post('/create', async (req, res) => {
  const { email, password } = req.body
  const userExists = (await getUser(email)) !== null

  // If a field is missing, return error
  if (!email || !password) {
    return res.status(400).json({ msg: MISSING_EMAIL_OR_PASSWORD })
  }
  // If the user already exists, return error
  if (userExists) {
    return res.status(400).json({ msg: USER_ALREADY_EXISTS })
  }
  // Set password security requirements
  if (password.length < 8 || password.includes(' ')) {
    return res.status(400).json({ msg: PASSWORD_REQUIREMENTS })
  }

  // Since all requirements are made, the account can be saved after
  // the password is hashed. If for some reason there is an error,
  // an error is sent as a respose
  const salt = await bcrypt.genSalt()
  const passwordHash = await bcrypt.hash(password, salt)
  const createdSuccessfully = await createUser(email, passwordHash)
  if (createdSuccessfully) {
    return res.status(201).json({
      msg: ACCOUNT_CREATED_SUCCESSFULLY
    })
  } else {
    return res.status(500).json({ msg: SERVER_CREATION_ERROR })
  }
})

// Logs a user in with an email and password. Responds with the token
// and refresh token under header { token, refreshToken }
tokenRouter.post('/login', async (req, res) => {
  // Note that the provided credentials are set to email, password
  // whereas the database credentials are user.email and user.password
  const { email, password } = req.body
  const user = await getUser(email)

  // If a field is missing, return error
  if (!email || !password) {
    return res.status(400).json({ msg: MISSING_EMAIL_OR_PASSWORD })
  }
  // If the user doesn't exist, return error
  if (user === null) {
    return res.status(400).json({ msg: USER_DOESNT_EXIST })
  }

  // Ensures that the password given is the same as the hashed
  // password stored in the database
  const authenticated = await bcrypt.compare(password, user.password)
  if (!authenticated) {
    return res.status(401).json({ msg: INVALID_PASSWORD })
  }

  const token = generateJWT(user.email)
  const refreshToken = generateRefreshJWT(user.email)
  addRefreshToken(refreshToken)
    .then(() => res.json({ token, refreshToken }))
    .catch(() => res.sendStatus(500))
})

// Gets a new token with authorization from the refresh token
tokenRouter.get('/refresh', (req, res) => {
  const authHeader = req.headers['authorization']
  const refreshToken = authHeader && authHeader.split(' ')[1]
  //Note the loose equals "==" as it may be either null or undefined
  if (refreshToken == null) {
    return res.sendStatus(401)
  }
  // If the refresh token does not exist, then access is denied
  if (!refreshTokenExists(refreshToken)) {
    return res.sendStatus(403)
  }

  jwt.verify(refreshToken, PRIVATE_REFRESH_KEY, (err, user) => {
    if (err) {
      return res.sendStatus(403)
    }
    const token = generateJWT(user.email)
    res.json({ token })
  })
})

// Removes the refresh token
tokenRouter.delete('/logout', (req, res) => {
  const token = req.body.token
  if (!token) {
    res.status(400).json({ msg: TOKEN_REQUIRED })
  }
  removeRefreshToken(token)
    .then(() => res.sendStatus(204))
    .catch(() => res.sendStatus(500))
})

module.exports = { tokenRouter, authenticateToken }
