require('dotenv').config()
const express = require('express')
const bodyParser = require("body-parser")
const cookieParser = require('cookie-parser')
const connectionMySql = require('./models/mysql/connectMysql')
const connectionMongoDB = require('./models/mongoDB/connectMongoDB')
const configCors = require('./config/cors')
const http = require('http')
const authRouter = require('./routers/authRouter')
const commentRouter = require("./routers/commentRouter")
const ratingRouter = require("./routers/ratingRouter")
const searchHisoryRouter = require('./routers/searchHistoryRouter')
const activityRouter = require("./routers/activityLogRouter")
const moviesRouter = require('./routers/moviesRouter')
const reportedCommentRouter = require("./routers/reportedCommentRouter")
const { configPassport } = require('./controller/passportController')
const configLoginWithGoogle = require('./controller/googleController')
const configSession = require('./config/session')
const initSocketIO = require('./socket')

const app = express()
const server = http.createServer(app);  
const io = require("socket.io")(server, {
    cors: {
        origin: process.env.REACT_URL,  
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 8080;

connectionMySql();
connectionMongoDB();

configCors(app);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(cookieParser());
configSession(app);
configPassport();
configLoginWithGoogle();

app.use('/auth', authRouter);
app.use('/comment', commentRouter);
app.use('/rating', ratingRouter);
app.use('/search-history', searchHisoryRouter);
app.use('/activity-log', activityRouter);
app.use('/movies', moviesRouter);
app.use('/reported-comment', reportedCommentRouter);

// Khởi tạo Socket.IO
initSocketIO(io);

server.listen(PORT, () => {  // Dùng server HTTP để lắng nghe
    console.log(`Server is running on http://localhost:${PORT}`);
});
