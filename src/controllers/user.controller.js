import {
  loginUserValidator,
  registerUserValidator,
  resetPasswordValidator,
} from '../validators/user.validator.js';
import {
  BadUserRequestError,
  NotFoundError,
  UnAuthorizedError,
} from '../errors/error.js';
import User from '../models/user.model.js';
import bcrypt from 'bcryptjs';
import { config } from '../config/index.js';
import { generateToken, verifyToken } from '../utils/jwt.utils.js';
import { sendEmail } from '../utils/sendEmail.js';
import crypto from 'crypto';

export default class UserController {
  static async register(req, res) {
    const { error } = registerUserValidator.validate(req.body);
    if (error) throw error;
    const { phone, email, rememberMe, country, fullName, password, role } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) throw new BadUserRequestError(`Account already exists. Please login!`);
    const saltRounds = config.bycrypt_salt_round;
    const hashedPassword = bcrypt.hashSync(password, saltRounds);
    const newUser = new User({
      phone,
      rememberMe,
      country,
      fullName,
      email,
      role,
      password: hashedPassword,
    });
    const token = generateToken(newUser);
    newUser.accessToken = token;
    await newUser.save()
    const user = newUser.toObject();
    delete user.password;
    const maxAge = config.cookie_max_age;
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge,
    });
    res.status(201).json(user);
  }

  // static async verifyOtp(req, res) {
  //   const { signUpOtp } = req.body;
  //   const user = await User.findOne({ signUpOtp });
  //   if (!user) throw new UnAuthorizedError('Invalid OTP');
  //   res.status(200).json();
  // }

  // static async registerUser(req, res) {
  //   const {
  //     email,
  //     securityQuestion,
  //     securityAnswer,
  //     firstName,
  //     surname,
  //     password,
  //   } = req.body;
  //   const { error } = registerUserValidator.validate(req.body);
  //   if (error) throw error;
  //   const validUser = await User.findOne({ email });
  //   if (!validUser) throw new UnAuthorizedError('Invalid request!');
  //   if (validUser.isVerified)
  //     throw new BadUserRequestError(
  //       'You have been verified already. Please login.',
  //     );
  //   const saltRounds = config.bycrypt_salt_round;
  //   const hashedPassword = bcrypt.hashSync(password, saltRounds);
  //   const token = generateToken(validUser);
  //   validUser.signUpOtp = null;
  //   validUser.isVerified = true;
  //   validUser.accessToken = token;
  //   validUser.securityQuestion = securityQuestion;
  //   validUser.securityAnswer = securityAnswer;
  //   validUser.firstName = firstName;
  //   validUser.surname = surname;
  //   validUser.password = hashedPassword;
  //   await validUser.save();
  //   const user = validUser.toObject();
  //   delete user.password;
  //   const maxAge = config.cookie_max_age;
  //   res.cookie('access_token', token, {
  //     httpOnly: true,
  //     secure: true,
  //     sameSite: 'none',
  //     maxAge,
  //   });
  //   res.status(201).json();
  // }

  static async loginUser(req, res) {
    const { error } = loginUserValidator.validate(req.body);
    if (error) throw new BadUserRequestError('Invalid login details');
    const { email, password } = req.body;
    const validUser = await User.findOne({ email }).select('+password');
    if (!validUser) throw new UnAuthorizedError('Invalid login details');
    // if (!validUser.isVerified)
    //   throw new UnAuthorizedError('Invalid login details');
    const isMatch = bcrypt.compareSync(password, validUser.password);
    if (!isMatch) throw new UnAuthorizedError('Invalid login details');
    const token = generateToken(validUser);
    validUser.accessToken = token;
    await validUser.save();
    const user = validUser.toObject();
    delete user.password;
    const maxAge = config.cookie_max_age;
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge,
    });

    res.status(200).json({
      status: 'Success',
      message: 'Login successful',
      user,
    });
  }

  static async logout(req, res) {
    const userId = req.user._id;
    const user = await User.findById(userId);
    user.accessToken = null;
    await user.save();
    res.cookie('access_token', '', {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      expires: new Date(0),
    });
    res.status(200).json({
      status: 'Success',
      message: 'Logout successful',
    });
  }

  static async getUser(req, res) {
    const userId = req.user._id;
    // const id = req.params.id
    // if (userId !== id) throw new UnAuthorizedError('Unauthorized!')
    const user = await User.findById(userId).select('-password');
    if (!user) throw new NotFoundError('User not found');
    res.status(200).json({
      status: 'Success',
      user,
    });
  }

  static async getLoginStatus(req, res) {
    const token = req.cookies.access_token;
    const verified = verifyToken(token);
    if (verified) {
      res.json(true);
    } else {
      res.json(false);
    }
  }

  static async forgotPassword(req, res) {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) throw new NotFoundError('User Not Found!!!');
    if (!user.isVerified) throw new NotFoundError('User Not Found!!!');
    res.status(200).json();
  }

  static async resetPasswordQuestion(req, res) {
    const { securityQuestion, securityAnswer, email } = req.body;
    const user = await User.findOne({ email });
    if (!user) throw new NotFoundError('User Not Found');
    if (
      securityQuestion !== user.securityQuestion ||
      securityAnswer.toLowerCase() !== user.securityAnswer
    )
      throw new UnAuthorizedError('Wrong Security Details');
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    await user.save();
    const resetPasswordUrl = `${req.protocol}://${req.get(
      'host',
    )}/resetpassword/verify/${resetToken}`;
    console.log(resetPasswordUrl);
    const message = `Hello ${user.firstName},\n\nPlease click on the following link to reset your password: ${resetPasswordUrl}\n\nPlease ignore this message if this request did not emanate from you.\n\nThank you.`;

    const mailSent = await sendEmail({
      email: user.email,
      subject: 'Reset Password Link',
      message,
    });
    if (mailSent === false)
      throw new NotFoundError(
        `${email} cannot be reached. Please provide a valid email address`,
      );
    res.status(200).json();
  }

  static async resetPassword(req, res) {
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(req.params.resetPasswordToken)
      .digest('hex');
    const { password } = req.body;
    const { error } = resetPasswordValidator.validate(req.body);
    if (error) throw error;
    const validUser = await User.findOne({ resetPasswordToken });
    if (!validUser) throw new BadUserRequestError('Invalid Request!!!');
    const saltRounds = config.bycrypt_salt_round;
    const hashedPassword = bcrypt.hashSync(password, saltRounds);
    validUser.password = hashedPassword;
    validUser.resetPasswordToken = null;
    await validUser.save();
    res.status(200).json();
  }

  static async deleteAll(req, res) {
    const users = await User.find();
    if (users.length < 1) throw new NotFoundError('No user found');
    const deleteUsers = await User.deleteMany();
    res.status(200).json({
      status: 'All users deleted successfully',
    });
  }
}
