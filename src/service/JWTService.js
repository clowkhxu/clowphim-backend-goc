require('dotenv').config()
const jwt = require('jsonwebtoken');
const db = require('../models/mysql/index')

const createJWT = (payload) => {
    let token = null
    try {
        token = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN
        })

        return token
    } catch (error) {
        console.log(error)
    }
}

const verifyToken = (token) => {
    let decoded = null
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET)
    } catch (error) {
        decoded = 'TokenExpiredError'
        console.log('TokenExpiredError')
    }
    return decoded
}

const insertTokenToDB = async (email, token, typeAccount) => {
    try {
        const rows = await db.Users.update(
            { refresh_token: token },
            { where: { email: email, type_account: typeAccount } }
        )

        if (rows[0] === 0) {
            return {
                EC: -1,
                EM: 'Thêm token thất bại!'
            }
        }

    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}

const findUserByToken = async (token) => {
    try {
        const user = await db.Users.findOne({
            where: { refresh_token: token },
            raw: true
        })

        if (!user) {
            return {
                EC: -1,
                EM: 'Không tìm thấy người dùng!',
                DT: ''
            }
        }

        return {
            EC: 0,
            EM: 'Tìm thấy người dùng!',
            DT: user
        }
    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}

const insertTokenToCookies = (res, accessToken, refreshToken) => {
    try {

        res.cookie('refresh_token', refreshToken, {
            maxAge: +process.env.MAX_AGE_REFRESH_TOKEN,
            httpOnly: true,
            secure: true,
            sameSite: 'none',
        });


        res.cookie('access_token', accessToken, {
            maxAge: +process.env.MAX_AGE_ACCESS_TOKEN,
            httpOnly: true,
            secure: true,
            sameSite: 'none',
        });

    } catch (error) {
        console.log(error)
        return res.status(500).json({
            EC: -1,
            EM: 'Lỗi không xác định!'
        })
    }
}

module.exports = {
    createJWT,
    verifyToken,
    insertTokenToDB,
    findUserByToken,
    insertTokenToCookies
}