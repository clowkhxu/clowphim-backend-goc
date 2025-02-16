require('dotenv').config();

const handleClearCookie = (res, cookieName) => {
    res.clearCookie(cookieName, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        path: '/'
    });
}

const handleInsertTokeToCookies = (res, accessToken, refreshToken) => {
    try {
        res.cookie('refresh_token', refreshToken, {
            maxAge: +process.env.MAX_AGE_REFRESH_TOKEN,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        });

        res.cookie('access_token', accessToken, {
            maxAge: +process.env.MAX_AGE_ACCESS_TOKEN,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        });
    } catch (error) {
        console.log('Error:', error)
    }
}

module.exports = {
    handleClearCookie,
    handleInsertTokeToCookies
};