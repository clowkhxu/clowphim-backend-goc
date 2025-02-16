require('dotenv').config()
const { createJWT } = require('../service/JWTService')
const { v4: uuidv4 } = require('uuid');
const JWTService = require('../service/JWTService');
const { handleInsertTokeToCookies } = require('../utils');

const verifyToken = async (req, res, next) => {
    try {
        const payload = {
            id: req?.user?.id,
            username: req?.user?.username,
            email: req?.user?.email,
            gender: req?.user?.gender,
            phone_number: req?.user?.phone_number,
            address: req?.user?.address,
            type_account: req?.user?.type_account,
        }

        return res.status(200).json({
            EC: 0,
            EM: 'Xác thực người dùng thành công!',
            DT: payload
        })
    } catch (error) {
        console.log(error)
        return res.status(500).json({
            EC: -1,
            EM: 'Lỗi không xác định!'
        })
    }
}


module.exports = {
    verifyToken,
}