'use strict';
const {
    Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
    class Users extends Model {
        /**
         * Helper method for defining associations.
         * This method is not a part of Sequelize lifecycle.
         * The `models/index` file will call this method automatically.
         */
        static associate(models) {
            // define association here
            Users.hasMany(models.Comments, {
                foreignKey: 'user_id',
                as: 'comments'
            });
        }
    }
    Users.init({
        username: DataTypes.STRING,
        email: DataTypes.STRING,
        phone_number: DataTypes.STRING,
        gender: DataTypes.STRING,
        password: DataTypes.STRING,
        address: DataTypes.STRING,
        is_lock: DataTypes.BOOLEAN,
        type_account: DataTypes.STRING,
        refresh_token: DataTypes.STRING
    }, {
        sequelize,
        modelName: 'Users',
    });
    return Users;
};