
import { body } from "express-validator";

// Validator for the register route
const userRegisterValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required!")
      .isEmail()
      .withMessage("Invalid email format!"),

    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required!")
      .isLowercase()
      .withMessage("Username must be in lowercase!")
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters long!"),

    body("password")
      .trim()
      .notEmpty()
      .withMessage("Password is required!")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters long!"),

    body("fullName").trim().notEmpty().withMessage("Full name is required!"),
  ];
};

// Validator for the login route
const userLoginValidator = () => {
  return [
    body("email").optional().isEmail().withMessage("Email is invalid!"),

    body("password").notEmpty().withMessage("Passowrd is required!"),
  ];
};

// Validator for the password change
const userChangeCurrentPasswordValidator = () => {
  return [
    body("oldPassword").notEmpty().withMessage("Old passowrd is required!"),
    body("newPassword").notEmpty().withMessage("New password is required!"),
  ];
};

// Validator for the forgot password
const userForgotPasswordValidator = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("Email is required!")
      .isEmail()
      .withMessage("Email is invalid!"),
  ];
};

// Validator for the reset forgot passowrd
const userResetForgotPasswordValidator = () => {
  return [body("newPassword").notEmpty().withMessage("Password is required!")];
};

export {
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
};
