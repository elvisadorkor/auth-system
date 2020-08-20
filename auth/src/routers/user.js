const express = require('express')
const User = require('../models/User') 
const auth = require('../middleware/auth')

const router = express.Router()



module.exports.router = router