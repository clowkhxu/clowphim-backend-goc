'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class OTPs extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
    }
  }
  OTPs.init({
    email: DataTypes.STRING,
    code: DataTypes.STRING,
    type_otp: DataTypes.STRING
  }, {
    sequelize,
    modelName: 'OTPs',
  });
  return OTPs;
};