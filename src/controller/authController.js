const authService = require("../service/authService")
const JWTService = require('../service/JWTService')
const nodemailer = require("nodemailer");
const handlebars = require('handlebars');
const fs = require('fs');
const path = require('path');
const { handleInsertTokeToCookies } = require("../utils");

const sendOTP = async (req, res) => {
    try {

        const OTP = Math.floor(100000 + Math.random() * 900000)

        const templatePath = req.body?.type_otp === 'REGISTER'
            ? '../templates/register.html'
            : '../templates/forgot-password.html';

        // Đọc và biên dịch mẫu email
        const filePath = path.join(__dirname, templatePath);
        const source = fs.readFileSync(filePath, 'utf-8').toString();
        const template = handlebars.compile(source);

        const replacements = {
            email: process.env.GOOGLE_APP_EMAIL,
            otp: OTP
        };

        const htmlToSend = template(replacements);

        const transporter = nodemailer.createTransport({
            host: "smtp.gmail.com",
            port: 587,
            secure: false,
            auth: {
                user: process.env.GOOGLE_APP_EMAIL,
                pass: process.env.GOOGLE_APP_PASSWORD,
            },
        });

        const response = await transporter.sendMail({
            from: `phohoccode <${process.env.GOOGLE_APP_EMAIL}>`,
            to: `${req.body?.email}`,
            subject: "Xác minh tài khoản",
            text: "phohoccode",
            html: htmlToSend
        });

        if (response?.messageId) {
            const response = await authService.insertCodeToDB(req.body?.email, OTP, req.body?.type_otp)

            if (+response?.EC !== 0) {
                return res.status(401).json({
                    EC: response?.EC,
                    EM: response?.EM
                })
            }

            return res.status(200).json({
                EC: 0,
                EM: 'Đã gửi mã xác nhận. Vui lòng kiểm tra email của bạn!'
            })
        } else {
            return res.status(401).json({
                EC: -1,
                EM: 'Gửi mã xác nhận thất bại!'
            })
        }

    } catch (error) {
        console.log(error)
        return res.status(500).json({
            EC: -1,
            EM: 'Lỗi không xác định!'
        })
    }
}


const login = async (req, res) => {
    try {

        const data = await authService.handleLogin(req.body)

        if (data?.EC !== 0) {
            return res.status(402).json({
                EC: data?.EC,
                EM: data?.EM
            })
        }

        return res.status(200).json({
            EC: data.EC,
            EM: data.EM,
            DT: data.DT
        })
    } catch (error) {
        console.log(error)
        return res.status(500).json({
            EC: -1,
            EM: 'Lỗi không xác định!'
        })
    }
}


const resgister = async (req, res) => {
    try {

        const data = await authService.handleRegister(req.body)

        return res.status(200).json({
            EC: data.EC,
            EM: data.EM
        })
    } catch (error) {
        console.log(error)
        return res.status(500).json({
            EC: -1,
            EM: 'Lỗi không xác định!'
        })
    }
}

const forgotPassword = async (req, res, next) => {
    try {
        const data = await authService.handleResetPassword(req.body)

        return res.status(200).json({
            EC: data.EC,
            EM: data.EM,
        })
    } catch (error) {
        console.log(error)
        return res.status(500).json({
            EC: -1,
            EM: 'Lỗi không xác định!'
        })
    }
}

const updateUser = async (req, res) => {
    try {

        const data = await authService.handleUpdateUser(req.body)

        if (data?.EC !== 0) {
            return res.status(402).json({
                EC: data?.EC,
                EM: data?.EM
            })
        }

        const payload = {
            id: data?.DT?.id,
            username: data?.DT?.username,
            email: data?.DT?.email,
            gender: data?.DT?.gender,
            phone_number: data?.DT?.phone_number,
            address: data?.DT?.address,
            type_account: data?.DT?.type_account,
        }

        const accessToken = JWTService.createJWT(payload)

        req.user = {
            ...payload,
            access_token: accessToken,
            refresh_token: data?.DT?.refresh_token
        }

        // set cookies
        handleInsertTokeToCookies(res, accessToken, data?.DT?.refresh_token)

        return res.status(200).json({
            EC: data?.EC,
            EM: data?.EM,
            DT: {
                ...data?.DT,
                access_token: accessToken
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

const getUserAccount = (req, res) => {

    try {
        if (req.isAuthenticated()) {
            return res.json({
                EC: 0,
                EM: 'Xác thực người dùng thành công!',
                DT: req?.user ?? {}
            });
        } else {
            res.status(401).json({
                EC: 0,
                EM: 'Xác thực người dùng thất bại!',
                DT: {}
            });
        }
    } catch (error) {
        console.log(error)
        return res.status(500).json({
            EC: -1,
            EM: 'Lỗi không xác định!'
        })
    }

}

const getUserById = async (req, res) => {

    try {
        const { userId } = req.query
        const data = await authService.handleGetUserById(userId)

        return res.json({
            EC: data?.EC,
            EM: data?.EM,
            DT: data?.DT
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
    login,
    resgister,
    sendOTP,
    forgotPassword,
    updateUser,
    getUserAccount,
    getUserById
}