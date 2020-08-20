const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
require('dotenv').config()

const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        // use validator package to validate email
        validate: value => {
            if (!validator.isEmail(value)) {
                throw new Error({error: 'Invalid Email Address'})
            }
        }
    },
    password: {
        type: String,
        required: true,
        minLength: 7
    },
    refreshTokens: [{
            type: String,
            required: false
    }]
})

//pre save function enables us to do something before we save the user to the database
userSchema.pre('save', async function (next){
    // hash password before saving user model
    const user = this
    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 8)
    }
    next()
})

userSchema.methods.generateAuthToken = async function(){
    const user = this
    const accessToken = jwt.sign({_id: user._id}, process.env.JWT_KEY, { expiresIn: '1h' })
    const refreshToken = jwt.sign({_id: user._id}, process.env.JWT_KEY_REFRESH)
    //having list of tokens means user can be signed in on several devices
    user.refreshTokens = user.refreshTokens.concat(refreshToken)
    await user.save()
    return { accessToken, refreshToken }
}

userSchema.statics.findByCredentials = async (email, password) => {
    //find user by email and password
    const user = await User.findOne({email})
    if(!user) {
        throw new Error({error: 'Invalid login credentials'})
    } 
    const isPasswordMatch = await bcrypt.compare(password, user.password)
    if(!isPasswordMatch) {
        throw new Error ({error: 'Invalid login credentials'})
    }
    return user
}

const User = mongoose.model('User', userSchema)

module.exports = User