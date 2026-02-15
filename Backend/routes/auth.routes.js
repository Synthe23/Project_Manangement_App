import { Router } from "express";
import {
  changeCurrentPassword,
  forgotPasswordRequest,
  getcurrentUser,
  login,
  logoutUser,
  refreshAccessToken,
  registerUser,
  resendEmailVerification,
  resetForgetPassowrd,
  verifyEmail,
} from "../controllers/auth.controllers.js";
import { validate } from "../middlewares/validator.middleware.js";
import {
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userLoginValidator,
  userRegisterValidator,
} from "../validators/index.js";

import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

// Unsecured Routes
// Router for the register
router.route("/register").post(userRegisterValidator(), validate, registerUser);
// Router for the login
router.route("/login").post(userLoginValidator(), validate, login);
// Router for the verify-email
router.route("/verify-email/:verificationToken").get(verifyEmail);
// Router for the refresh-Token
router.route("/refresh-token").post(refreshAccessToken);
// Router for the forgot-passowrd
router
  .route("/forgot-password")
  .post(userForgotPasswordValidator(), validate, forgotPasswordRequest);
// Router for the reset-Password
router
  .route("/reset-password/:resetToken")
  .post(userRegisterValidator(), validate, resetForgetPassowrd);



// Secure routes (required jwt and authentication)
// Router for the logout
router.route("/logout").post(verifyJWT, logoutUser);
// Router for the current-user 
router.route("/current-user").post(verifyJWT, getcurrentUser);
// Router for the change-password
router
  .route("/change-password")
  .post(
    verifyJWT,
    userChangeCurrentPasswordValidator(),
    validate,
    changeCurrentPassword,
  );
  router.route("/resend-email-verification").post(verifyJWT, resendEmailVerification);

export default router;
