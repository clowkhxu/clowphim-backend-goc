require('dotenv').config()
const Sequelize = require("sequelize")
const session = require("express-session")
const passport = require('passport')

const configSession = (app) => {
    const SequelizeStore = require("connect-session-sequelize")(session.Store);

    const sequelize = new Sequelize(
        process.env.DB_NAME,
        process.env.DB_USERNAME,
        process.env.DB_PASSWORD, {
        host: process.env.DB_HOST,
        dialect: process.env.DB_DIALECT,
        logging: false,
        timezone: '+07:00'
    })

    // Tạo store để lưu trữ sesstion thông qua Sequelize:
    const myStore = new SequelizeStore({
        db: sequelize,
    })

    // Thiết lập middleware express-session:
    app.use(session({
        secret: process.env.SESSION_SECRET,
        store: myStore,
        resave: false,
        proxy: true,
        saveUninitialized: false,
        cookie: {
            maxAge: 86400000,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
        }
    }));

    // tạo bảng sesstion trong db
    myStore.sync()

    // xác thực người dùng dựa vào sesstion
    app.use(passport.authenticate('session'))

    // Mã hóa: chuyển định dạng user thành dạng có thể lưu trữ trong session
    passport.serializeUser(function (user, cb) {
        process.nextTick(function () {
            // console.log('>>> Mã hoá:', user)
            cb(null, user)
        });
    });

    // Giải mã hóa: chuyển định dạng từ session trở lại thành đối tượng user
    passport.deserializeUser(function (user, cb) {
        process.nextTick(function () {
            // console.log('>>> Giãi mã hoá:', user)
            return cb(null, user);
        });
    });
}

module.exports = configSession