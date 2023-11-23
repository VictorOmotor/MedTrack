import { Router } from 'express';
import UserController from '../controllers/user.controller.js';
import { tryCatchHandler } from '../utils/tryCatch.handler.js';
import { userAuthMiddleWare } from '../middlewares/auth.middleware.js';

const router = Router();

router.post('/signup', tryCatchHandler(UserController.register));
// router.post('/verifyotp', tryCatchHandler(UserController.verifyOtp));
// router.post(
//   '/signup/security-question',
//   tryCatchHandler(UserController.registerUser),
// );
router.post('/login', tryCatchHandler(UserController.loginUser));
router.get(
  '/logout',
  userAuthMiddleWare,
  tryCatchHandler(UserController.logout),
);

router.post('/forgotpassword', tryCatchHandler(UserController.forgotPassword));
router.post(
  '/resetpassword/security-question',
  tryCatchHandler(UserController.resetPasswordQuestion),
);

router.post(
  '/resetpassword/reset/:resetPasswordToken',
  tryCatchHandler(UserController.resetPassword),
);

router.delete('/deleteall', tryCatchHandler(UserController.deleteAll));

export { router };
