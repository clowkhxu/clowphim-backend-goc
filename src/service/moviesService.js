const SavedMovies = require('../models/mongoDB/savedMovies')
const WatchHistory = require("../models/mongoDB/watchHistory")

const handleGetALlMovies = async (rawData) => {
    try {
        const { userId, type } = rawData
        let data;
        type === 'saved-movies' ?
            data = await SavedMovies.findOne({ userId }) :
            data = await WatchHistory.findOne({ userId });

        if (!data || data?.movies?.length === 0) {
            return {
                EC: 0,
                EM: type === 'saved-movies' ? 'Danh sách phim đang trống!' : 'Lịch sử xem đang trống!',
                DT: {
                    type,
                    movies: []
                }
            };
        }

        return {
            EC: 0,
            EM: 'Lấy bộ phim đã lưu thành công!',
            DT: {
                type,
                movies: data?.movies.reverse() ?? []
            }
        };
    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}

const handleAddMovie = async (rawData) => {
    try {
        const { userId, movieInfo, type } = rawData
        let data;
        type === 'saved-movies' ?
            data = await SavedMovies.findOne({ userId }) :
            data = await WatchHistory.findOne({ userId })

        if (!data) {
            data = type === 'saved-movies' ?
                new SavedMovies({ userId, movies: [] }) :
                new WatchHistory({ userId, movies: [] })
        }

        const isExist = data.movies.some(movie => movie.slug === movieInfo.slug)

        if (!isExist) {
            data.movies.push(movieInfo);
            await data.save();
        }
        return {
            EC: 0,
            EM: 'Phim đã được lưu thành công!',
            DT: data ?? []
        }
    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}

const handleDeleteMovie = async (rawData) => {
    try {
        const { userId, movieSlug, type } = rawData
        let data

        type === "saved-movies" ?
            data = await SavedMovies.findOne({ userId }) :
            data = await WatchHistory.findOne({ userId })

        if (data?.movies) {
            data.movies = data?.movies.filter(item => item.slug !== movieSlug)
            await data.save();
        }

        return {
            EC: 0,
            EM: "Xoá phim thành công!"
        }

    } catch (error) {
        console.log(error)
        return {
            EC: -1,
            EM: 'Lỗi không xác định!'
        }
    }
}


const handleDeleteAll = async (rawData) => {
    try {
        const { userId, type } = rawData
        type === 'saved-movies' ?
            await SavedMovies.deleteMany({ userId }) :
            await WatchHistory.deleteMany({ userId })

        return {
            EC: 0,
            EM: type === 'saved-movies' ? "Tất cả phim đã lưu đã bị xoá!" : "Đã xoá lịch sử xem!"
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
    handleDeleteAll,
    handleGetALlMovies,
    handleAddMovie,
    handleDeleteMovie
}