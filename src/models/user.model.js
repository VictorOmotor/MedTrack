import { Schema, model, Types } from 'mongoose';

const UserSchema = new Schema(
  {
    fullName: {
      type: String,
      trim: true,
    },
    // firstName: {
    //   type: String,
    //   trim: true,
    // },
    // surname: {
    //   type: String,
    //   trim: true,
    // },
    email: {
      type: String,
      unique: true,
      trim: true,
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        'Please enter a valid email',
      ],
    },
    password: {
      type: String,
      trim: true,
      select: false,
    },
    country: {
      type: String,
      trim: true,
    },
    phone: {
      type: String,
      required: true,
      unique: true,
    },
    accessToken: {
      type: String,
      default: null,
    },
    imageUrl: String,
    rememberMe: {
      type: Boolean,
      default: false,
    },
    // isVerified: {
    //   type: Boolean,
    //   default: false,
    // },
    // signUpOtp: {
    //   type: String,
    //   default: null,
    // },
    role: {
      type: String,
      enum: ['user', 'physician'],
    },
    resetPasswordToken: {
      type: String,
      default: null,
    },
  },
  {
    timestamps: true,
  },
);

export default model('User', UserSchema);
