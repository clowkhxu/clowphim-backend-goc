require('dotenv').config()
const express = require('express')
const authController = require("../controller/authController")
const passportController = require('../controller/passportController')
const passport = require('passport')
const JWTController = require("../controller/JWTController")
const JWTActions = require('../middleware/JWTActions')

const route = express.Router()

route.all("*", JWTActions.verifyJWT)
route.post('/login', passportController.handleLogin)
route.get('/logout', passportController.handleLogout)
route.post('/register', authController.resgister)
route.post('/send-otp', authController.sendOTP)
route.post('/verify-token', JWTController.verifyToken)
route.post('/forgot-password', authController.forgotPassword)
route.post('/update-user', authController.updateUser)
route.get('/user-account', authController.getUserAccount);
route.get('/another-user-account', authController.getUserById);

route.get('/google',
    passport.authenticate('google', { scope: ['profile', 'email'] }));

route.get('/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        const { code, type_account } = req.user
        res.redirect(`${process.env.REACT_URL}/authenticate?token=${code}&type=${type_account}`);
    });



module.exports = route