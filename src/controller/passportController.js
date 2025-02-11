const passport = require('passport');
const LocalStrategy = require('passport-local');
const authService = require('../service/authService');
const { handleClearCookie } = require('../utils');

const configPassport = () => {
    passport.use(new LocalStrategy({ usernameField: "email" },
        async function (email, password, done) {
            const response = await authService.handleLogin({ email, password })

            if (response && +response.EC === 0) {
                return done(null, response.DT, response.EM);
            } else {
                return done(null, false, response.EM);
            }
        }
    ));
}

const handleLogin = (req, res, next) => {
    passport.authenticate('local', function (error, user, info) {
        if (error) {
            return res.status(500).json(error);
        }

        if (!user) {
            return res.status(402).json({
                EC: -1,
                EM: info
            });
        }

        // Lưu thông tin người dùng vào session và cookies 
        req.login(user, function (err) {
            if (err) return next(err)
            return res.status(200).json(user)
        })

    })(req, res, next)
}

const handleLogout = (req, res, next) => {
    req.logout(function (err) {
        if (err) { return next(err); }

        handleClearCookie(res, 'refresh_token');
        handleClearCookie(res, 'access_token');

        res.json({
            EC: 0,
            EM: 'Đăng xuất tài khoản thành công!'
        })
    });
}

module.exports = {
    configPassport,
    handleLogin,
    handleLogout
}
