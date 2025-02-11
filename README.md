# 1. Hướng dẫn setup dự án

## 1/ Clone dự án

```bash
  https://github.com/phohoccode/phoflix-v2-backend.git
```

## 2/ Cài đặt node_modules

```bash
  npm i
```

## 3/ Chạy dự án

```bash
  npm start
```

## 4/ Tạo các bảng cần thiết

```bash
  npx sequelize-cli db:migrate
```


# 2. Biến môi trường tuỳ chỉnh
`NODE_ENV=development`
`PORT=8080`
`REACT_URL=http://localhost:3000`
`JWT_SECRET=Tuỳ chỉnh`
`SESSION_SECRET=Tuỳ chỉnh`
`JWT_EXPIRES_IN=30s`
`MAX_AGE_ACCESS_TOKEN=3600000` 
`MAX_AGE_REFRESH_TOKEN=86400000`

## 1. Cấu hình MySql khi sử dụng xampp
### Hướng dẫn kiểm tra và tạo cơ sở dữ liệu trong XAMPP:
#### 1. Cài đạt XAMPP:
#### 2. Mở XAMPP Control Panel.
#### 3. Nhấn nút Apache ở hàng MySQL.
#### 4. Nhấn nút Start ở hàng MySQL.
#### 5. Truy cập phpMyAdmin: http://localhost/phpmyadmin.
#### 6. Tạo Database: Nhấn vào nút New.
#### 7. Nhập tên database (ví dụ: my_database) và nhấn nút Create.

`DB_USERNAME=root`
`DB_NAME=my_database`
`DB_PASSWORD=null`
`DB_HOST=localhost`
`DB_DIALECT=mysql`

## 2. Cấu hình MongoDB trên MongoDBCompass
### Hướng dẫn kiểm tra và tạo cơ sở dữ liệu trong MongoDB Compass
#### 1. Nếu chưa cài đặt, bạn có thể tải từ: https://www.mongodb.com/try/download/community.
#### 2. Mở MongoDB Compass.
#### 3. Nhấn nút Add new connection

`MONGO_URI=mongodb://localhost:27017`

## 3. Cấu hình Google Cloud 
### 1. Đăng nhập Google Cloud Console
#### 1. Truy cập: Google Cloud Console
#### 2. Đăng nhập bằng tài khoản Google của bạn.
### 2. Tạo một dự án mới
#### 1.Trong trang chính của Google Cloud Console, nhấn Select a Project (hoặc Create Project nếu chưa có dự án).
#### 2. Nhấn New Project, đặt tên cho dự án và nhấn Create.
### 3. Bật API Google OAuth
#### 1. Trong dự án của bạn, vào API & Services > Enabled APIs & Services.
#### 2. Nhấn Enable APIs and Services.
#### 3. Tìm kiếm "OAuth 2.0 Client ID" và bật dịch vụ liên quan.
### 4. Tạo thông tin xác thực OAuth
#### 1. Vào API & Services > Credentials.
#### 2. Nhấn Create Credentials > OAuth 2.0 Client IDs.
#### 3. Chọn Web application
#### 4. Điền thông tin
#### 5. Nhập URL callback dùng trong ứng dụng của bạn ví dụ: http://localhost:3000/auth/google/callback
### 5. Lấy thông tin OAuth

`GOOGLE_APP_CLIENT_ID=YOUR_CLIENT_ID`
`GOOGLE_APP_CLIENT_SECRET=YOUR_CLIENT_SECRET`
`GOOGLE_APP_CALLBACK=http://localhost:3000/auth/google/callback`


##  4. Cấu hình tài khoản gửi mail 
### 1. Truy cập Gmail và đăng nhập vào tài khoản bạn muốn sử dụng để gửi email.
### 2. Truy cập Google Account Security.
#### 4. Tìm mục "App Passwords" (mật khẩu ứng dụng). 
##### 5. Nếu không thấy tùy chọn này, bạn cần bật 2-step verification Vào Security > 2-Step Verification > Làm theo hướng dẫn để bật.
#### 6. Sau khi bật 2-step verification, bạn sẽ thấy mục App Passwords.
### 7. Nhấn App Passwords
### 8. Chọn loại ứng dụng
#### 9. Select App: Chọn Mail.
#### 10. Select Device: Chọn Other (Custom) và nhập tên như MyApp.
### 11. Nhấn Generate để tạo mật khẩu ứng dụng.
### 12. Sao chép mật khẩu được tạo (16 ký tự) để sử dụng trong ứng dụng.

`GOOGLE_APP_EMAIL=your_email@gmail.com`
`GOOGLE_APP_PASSWORD=generated_app_password`

