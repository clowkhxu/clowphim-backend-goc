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
    'another-user-account'
];

const verifyJWT = async (req, res, next) => {
    if (nonSecurePaths.includes(req.path)) return next();

    const accessToken = req.cookies?.access_token;
    const refreshToken = req.cookies?.refresh_token;

    console.log("🔹 Incoming request:", req.path);
    console.log("🔑 Access Token:", accessToken);
    console.log("🔄 Refresh Token:", refreshToken);

    if (!refreshToken) {
        return res.status(401).json({
            EC: -1,
            EM: 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại!'
        });
    }

    let decoded;
    try {
        decoded = JWTService.verifyToken(accessToken);
        console.log("✅ Token hợp lệ:", decoded);
    } catch (error) {
        console.error("❌ Token verification error:", error);
        if (error.name === 'TokenExpiredError') {
            console.log("🔄 Access token đã hết hạn, thử refresh token...");
        } else {
            return res.status(401).json({
                EC: -1,
                EM: 'Token không hợp lệ!'
            });
        }
    }

    if (decoded) {
        req.user = {
            ...decoded,
            access_token: accessToken,
            refresh_token: refreshToken
        };
        return next();
    }

    try {
        const response = await JWTService.findUserByToken(refreshToken);

        if (!response || +response.EC === -1) {
            console.log("❌ Refresh token không hợp lệ:", response);
            return res.status(401).json({
                EC: -1,
                EM: 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại!'
            });
        }

        console.log("✅ Refresh token hợp lệ, tạo access token mới...");

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

        // Cập nhật cookies
        handleInsertTokeToCookies(res, newAccessToken, refreshToken);

        return next();
    } catch (error) {
        console.error("❌ Lỗi khi xác thực refresh token:", error);
        return res.status(401).json({
            EC: -1,
            EM: 'Lỗi khi xác thực refresh token!'
        });
    }
};

module.exports = {
    verifyJWT
};
