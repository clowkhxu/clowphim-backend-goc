require('dotenv').config()
const { createJWT } = require('../service/JWTService')
const { v4: uuidv4 } = require('uuid');
const JWTService = require('../service/JWTService');
const { handleInsertTokeToCookies } = require('../utils');

const verifyToken = async (req, res, next) => {
    try {

        const ssoToken = req.body?.token

        if (req?.user?.code !== ssoToken) {
            return res.status(401).json({
                EC: -1,
                EM: 'Token không hợp lệ!'
            })
        }

        const refreshToken = uuidv4()
        const response =
            await JWTService.insertTokenToDB(req?.user?.email, refreshToken, req.body?.typeAccount)

        if (+response?.EC === -1) {
            return res.status(401).json({
                EC: response?.EC,
                EM: response?.EM
            })
        }

        const payload = {
            id: req?.user?.id,
            username: req?.user?.username,
            email: req?.user?.email,
            gender: req?.user?.gender,
            phone_number: req?.user?.phone_number,
            address: req?.user?.address,
            type_account: req?.user?.type_account,
        }

        const accessToken = createJWT(payload)

        // set cookies
        handleInsertTokeToCookies(res, accessToken, refreshToken)

        return res.status(200).json({
            EC: 0,
            EM: 'Xác thực người dùng thành công!',
            DT: {
                ...payload,
                access_token: accessToken,
                refresh_token: refreshToken
            }
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