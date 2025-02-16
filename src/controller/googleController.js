require('dotenv').config()
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const passport = require('passport')
const { v4: uuidv4 } = require('uuid');
const authService = require("../service/authService")

const configLoginWithGoogle = () => {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_APP_CLIENT_ID,
        clientSecret: process.env.GOOGLE_APP_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_APP_CALLBACK,
        passReqToCallback: true
    },
        async function (req, accessToken, refreshToken, profile, cb) {

            const rawData = {
                username: profile.displayName,
                email: profile?.emails?.[0]?.value,
                type: 'GOOGLE'
            }

            const user = await authService.findOrInsertProfileSocialToDB(rawData)
            user.code = uuidv4()

            return cb(null, user)
        }
    ));
}


module.exports = configLoginWithGoogle