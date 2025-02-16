const db = require('../models/mysql/index')
const bcrypt = require('bcryptjs');
const validator = require('validator');
const { v4: uuidv4 } = require('uuid');

const salt = bcrypt.genSaltSync(10);

const hashUserPassword = (password, salt) => {
    return bcrypt.hashSync(password, salt)
}

const checkPassword = (password, hashPassword) => {
    return bcrypt.compareSync(password, hashPassword)
}

const checkExistEmail = async (emailUser) => {
    try {
        const email = await db.Users.findOne({
            where: { email: emailUser, type_account: 'LOCAL' },
            raw: true
        })

        return email ? true : false
    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}

const insertCodeToDB = async (email, code, type) => {
    try {

        const user = await db.OTPs.findOne({
            where: { email: email, type_otp: type }
        })

        if (!user) {
            const response = await db.OTPs.create({
                email: email,
                code: code,
                type_otp: type
            })

            if (response?.isNewRecord) {
                return {
                    EC: -1,
                    EM: 'Thêm mã xác thực thất bại!'
                }
            } else {
                return {
                    EC: 0,
                    EM: 'Thêm mã xác thực thành công!'
                }
            }
        }

        const rows = await db.OTPs.update(
            { code: code },
            { where: { email: email, type_otp: type } }
        )

        if (rows[0] > 0) {
            return {
                EC: 0,
                EM: 'Cập nhật mã thành công!'
            }
        } else {
            return {
                EC: -1,
                EM: 'Cập nhật mã thất bại!'
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

const handleLogin = async (rawData) => {
    try {
        const user = await db.Users.findOne({
            where: {
                email: rawData?.email,
                type_account: 'LOCAL'
            },
            raw: true
        })

        if (!user) {
            return {
                EC: -1,
                EM: 'Thông tin đăng nhập không chính xác!'
            }
        }

        const isCorrectPassword = checkPassword(rawData?.password, user?.password)

        if (!isCorrectPassword) {
            return {
                EC: -1,
                EM: 'Thông tin đăng nhập không chính xác!'
            }
        }

        if (+user.isLock === 1) {
            return {
                EC: -1,
                EM: 'Tài khoản của bạn đã bị khoá!'
            }
        }

        return {
            EC: 0,
            EM: 'Đăng nhập thành công!',
            DT: {
                id: user?.id,
                username: user?.username,
                email: user?.email,
                address: user?.address,
                phone_number: user?.phone_number,
                gender: user?.gender,
                type_account: user?.type_account,
                code: uuidv4()
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

const handleRegister = async (rawData) => {
    try {

        const email = await checkExistEmail(rawData?.email)
        console.log(rawData)

        if (email) {
            return {
                EC: -1,
                EM: 'Email đã tồn tại!',
            }
        }

        const strongPassword = validator.isStrongPassword(rawData?.password)

        if (!strongPassword) {
            return {
                EC: -1,
                EM: 'Mật khẩu yếu! Yêu cầu ít nhất 8 ký tự, bao gồm chữ hoa, chữ thường, số và ký tự đặc biệt.',
            }
        }

        const user = await db.OTPs.findOne({
            where: { email: rawData?.email, type_otp: rawData?.type_otp },
            raw: true
        })

        if (!user || user?.code !== rawData?.code) {
            return {
                EC: -1,
                EM: 'Mã xác nhận không chính xác!',
            }
        }

        const hashPassword = hashUserPassword(rawData?.password, salt)

        const response = await db.Users.create({
            id: uuidv4(),
            username: rawData?.username,
            email: rawData?.email,
            password: hashPassword,
            gender: "Nam",
            isLock: false,
            phone_number: "",
            address: "",
            type_account: 'LOCAL'
        })

        if (response?.isNewRecord) {
            return {
                EC: 0,
                EM: 'Đăng ký tài khoản thất bại!',
            }
        }

        return {
            EC: 0,
            EM: 'Đăng ký tài khoản thành công!',
        }
    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}

const findOrInsertProfileSocialToDB = async (rawData) => {
    try {
        let user = null

        user = await db.Users.findOne({
            where: { email: rawData?.email, type_account: rawData?.type },
            raw: true
        })

        if (!user) {
            user = await db.Users.create({
                id: uuidv4(),
                username: rawData?.username,
                email: rawData?.email,
                type_account: rawData?.type
            })

            user = user?.dataValues
        }
        return user
    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}

const handleResetPassword = async (rawData) => {
    try {
        const isEmailExist = await checkExistEmail(rawData?.email)

        if (!isEmailExist) {
            return {
                EC: -1,
                EM: 'Địa chỉ email không tồn tại!'
            }
        }

        const strongPassword = validator.isStrongPassword(rawData?.password)

        if (!strongPassword) {
            return {
                EC: -1,
                EM: 'Mật khẩu yếu! Yêu cầu ít nhất 8 ký tự, bao gồm chữ hoa, chữ thường, số và ký tự đặc biệt.',
            }
        }

        const user = await db.OTPs.findOne({
            where: { email: rawData?.email, type_otp: rawData?.type_otp },
            raw: true
        })


        if (!user || user?.code !== rawData?.code) {
            return {
                EC: -1,
                EM: 'Mã xác nhận không chính xác!',
            }
        }

        const hashPassword = hashUserPassword(rawData?.password)

        const rows = await db.Users.update(
            { password: hashPassword },
            { where: { email: rawData?.email } }
        )

        if (rows[0] === 0) {
            return {
                EC: -1,
                EM: 'Thay đổi mật khẩu thất bại!'
            }
        }

        return {
            EC: 0,
            EM: 'Thay đổi mật khẩu thành công!'
        }
    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}

const handleUpdateUser = async (rawData) => {
    try {

        if (rawData?.phone_number && !validator.isMobilePhone(rawData?.phone_number)) {
            return {
                EC: -1,
                EM: 'Số điện thoại không hợp lệ!',
                DT: {}
            }
        }

        const rows = await db.Users.update(
            {
                username: rawData?.username,
                phone_number: rawData?.phone_number,
                gender: rawData?.gender,
                address: rawData?.address
            },
            { where: { email: rawData?.email, type_account: rawData?.type_account } }
        )


        if (rows[0] === 0) {
            return {
                EC: -1,
                EC: 'Cập nhật người dùng thất bại!',
                DT: {}
            }
        }

        const user = await db.Users.findOne({
            where: { email: rawData?.email, type_account: rawData?.type_account },
            raw: true
        })

        return {
            EC: 0,
            EM: 'Cập nhật thông tin thành công!',
            DT: {
                id: user?.id,
                username: user?.username,
                email: user?.email,
                address: user?.address,
                type_account: user?.type_account,
                gender: user?.gender,
                phone_number: user?.phone_number,
                refresh_token: user?.refresh_token,
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

const handleGetUserById = async (userId) => {
    try {
        const user = await db.Users.findOne({
            where: { id: userId }
        })

        if (!user) {
            return {
                EC: -1,
                EM: "Không tìm thấy thông tin người dùng!",
                DT: {}
            }
        }

        console.log('>>> user', user)
        return {
            EC: 0,
            EM: 'Lấy thông tin người dùng thành công!',
            DT: {
                id: user?.id,
                username: user?.username,
                gender: user?.gender,
                createdAt: user?.createdAt
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

module.exports = {
    handleRegister,
    handleLogin,
    insertCodeToDB,
    findOrInsertProfileSocialToDB,
    handleResetPassword,
    handleUpdateUser,
    handleGetUserById
}