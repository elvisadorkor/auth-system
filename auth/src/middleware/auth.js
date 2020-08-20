//middleware is piece of code that acts as bridge between the database and the application, especially on a network

const jwt = require("jsonwebtoken")
const User = require("../models/User")
const jwtDecode = require("jwt-decode")

const auth = async (req, res, next) => {
  //get token from request header
  //token comes in form 'Bearer[space]token', hence unnecessary needs to be replaced with ''
  const token = req.cookies.access_token
  if (!token || token === 'j:null') {
    res.redirect("/users/me/reauthenticate")
    return
  } 

  try {
    const data = jwt.verify(token, process.env.JWT_KEY)
    const user = await User.findOne({ _id: data._id })
    if (!user) {
      throw new Error()
    }
    req.user = user
    req.token = token
    next()
  } catch (error) {
    res.clearCookie('access_token')
    res.clearCookie('refresh_token')
    req.clearCookie('access_token')
    req.clearCookie('refresh_token')
    if (error.message === 'jwt expired') {
        res.redirect("/users/me/reauthenticate")
        return;
      }
    return res
      .status(400)
      .json({ error: "Not authorized to access this resource" })

  }
}

module.exports = auth
