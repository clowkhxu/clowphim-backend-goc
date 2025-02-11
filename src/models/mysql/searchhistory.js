'use strict';
const {
    Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
    class SearchHistory extends Model {
        /**
         * Helper method for defining associations.
         * This method is not a part of Sequelize lifecycle.
         * The `models/index` file will call this method automatically.
         */
        static associate(models) {
            // define association here
            SearchHistory.belongsTo(models.Users, {
                foreignKey: 'user_id',
                as: 'user'
            });
        }
    }
    SearchHistory.init({
        type: DataTypes.STRING,
        user_id: DataTypes.STRING,
        keyword: DataTypes.STRING
    }, {
        sequelize,
        modelName: 'SearchHistory',
    });
    return SearchHistory;
};