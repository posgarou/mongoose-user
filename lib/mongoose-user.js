
/*!
 * mongoose-user
 * Copyright(c) 2013 Madhusudhan Srinivasa <madhums8@gmail.com>
 * MIT Licensed
 */

var DEFAULT_VALIDATIONS = {
  password: [
    {
      validator: function(password) {
        return password && password.trim().length > 8;
      },
      message: "Password must be at least 8 characters",
    },
  ],
};

var VIRTUALS = [
  "password",
  "_password",
];


/**
 * Expose
 */

module.exports = userPlugin

/**
 * User plugin
 *
 * Some common methods and statics to user schema
 *
 * @param {Schema} schema
 * @param {Object} options
 * @param {Object[]} options.validations keyed by property being validated
 * @api public
 */

function userPlugin (schema, options) {
  var crypto = require('crypto')

  var defaultsDeep = require("lodash/object/defaultsDeep");

  options || options = {};

  defaultsDeep(options, {
    validations: DEFAULT_VALIDATIONS,
  });

  var validations = options.validations;

  /**
   * Attributes
   **/
  schema.add({
    "_hashed_password": {
      type: String,
      default: "",
    },
    "salt": {
      type: String,
      default: "",
    },
  });

  /**
   * Model methods
   **/

  /**
   * Authenticate by checking the hashed password and provided password
   *
   * @param {String} plainText
   * @return {Boolean}
   * @api private
   */

  schema.methods.authenticate = function(plainText) {
    return this.encryptPassword(plainText) === this._hashed_password
  }

  /**
   * Create password salt
   *
   * @return {String}
   * @api private
   */

  schema.methods.makeSalt = function() {
    return Math.round((new Date().valueOf() * Math.random())) + ''
  }

  /**
   * Encrypt password
   *
   * @param {String} password
   * @return {String}
   * @api private
   */

  schema.methods.encryptPassword = function (password) {
    if (!password) return ''
    return crypto.createHmac('sha1', this.salt).update(password).digest('hex')
  }

  /**
   * Virtuals
   */

  /**
   * Password virtual
   */

  schema.virtual('password')
  .set(function(password) {
    var validationSet = validations.password;

    if (validationSet) {
      if (!Array.isArray(validationSet)) {
        validationSet = [validationSet];
      }

      validationSet.forEach(function(validation) {
        if (!validation.validator(password)) {
          this.invalidate(
            "password",
            validation.message || "Password is invalid",
            password
          );
        }
      });
    }

    this._password = password
    this.salt = this.makeSalt()
    this._hashed_password = this.encryptPassword(password)
  })
  .get(function() {
    return this._password
  })

  /**
   * Validations
   **/

  for (var key in validations) {
    // We don't want to setup mongoose validations for virtual paths
    if (VIRTUALS.indexOf(key) !== -1) continue;

    schema.path(key).validate(validations[key]);
  }
}
