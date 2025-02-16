
module.exports = (io) => {

    io.on('connection', (socket) => {
        console.log('Kết nối mới', socket.id);

        socket.on('addComment', (data) => {
            console.log("Có bình luận mới!");
            io.emit('refreshComments', { slug: data?.slug });
        });

        socket.on('updateComment', (data) => {
            console.log("Có bình luận vừa cập nhật!");
            io.emit('refreshComments', { slug: data?.slug });
        });

        socket.on('deleteComment', (data) => {
            console.log("Có bình luận vừa xóa!");
            io.emit('refreshComments', { slug: data?.slug });
        })

        socket.on("addRating", (data) => {
            console.log("Có đánh giá mới!");
            io.emit('refreshRating', { slug: data?.slug });
        });

        socket.on('disconnect', () => {
            console.log('Đã ngắt kết nối', socket.id);
        });
    });
};
