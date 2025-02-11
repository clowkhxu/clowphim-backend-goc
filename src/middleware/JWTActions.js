const JWTService = require('../service/JWTService');
const { handleInsertTokeToCookies } = require('../utils');

const nonSecurePaths = [
    '/logout',
    '/forgot-password',
    '/login',
    '/register',
    '/verify-token',
    '/google',
    '/google/callback',
    '/send-otp',
    'another-user-account'];

const verifyJWT = async (req, res, next) => {
    if (nonSecurePaths.includes(req.path)) return next();

    const accessToken = req.cookies?.access_token;
    const refreshToken = req.cookies?.refresh_token;

    if (!refreshToken) {
        return res.status(401).json({
            EC: -1,
            EM: 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại!'
        });
    }

    let decoded;
    try {
        decoded = JWTService.verifyToken(accessToken);
        req.user = {
            ...decoded,
            access_token: accessToken,
            refresh_token: refreshToken
        };
        return next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            const response = await JWTService.findUserByToken(refreshToken);

            if (!response || response.EC === -1) {
                return res.status(401).json({
                    EC: -1,
                    EM: 'Phiên đăng nhập đã hết hạn hoặc không hợp lệ!'
                });
            }

            const payload = {
                id: response.DT.id,
                username: response.DT.username,
                email: response.DT.email,
                gender: response.DT.gender,
                phone_number: response.DT.phone_number,
                address: response.DT.address,
                type_account: response.DT.type_account,
            };

            const newAccessToken = JWTService.createJWT(payload);
            req.user = {
                ...payload,
                access_token: newAccessToken,
                refresh_token: refreshToken
            };

            // Cập nhật cookies với token mới
            handleInsertTokeToCookies(res, newAccessToken, refreshToken);

            return res.status(401).json({
                EC: -1,
                EM: 'Phiên đăng nhập đã hết hạn! Token mới đã được cấp.',
                accessToken: newAccessToken
            });
        }

        return res.status(401).json({
            EC: -1,
            EM: 'Token không hợp lệ hoặc đã hết hạn!'
        });
    }
};

module.exports = {
    verifyJWT
};
