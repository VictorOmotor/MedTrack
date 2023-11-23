import Joi from 'joi';

export const registerUserValidator = Joi.object({
  email: Joi.string().required(),
  fullName: Joi.string().required(),
  // firstName: Joi.string().required(),
  // surname: Joi.string().required(),
  password: Joi.string()
    .regex(
      /^(?=.*[A-Za-z])(?=.*\d)[a-zA-Z0-9!@#$%^&*()~¥=_+}{":;'?/>.<,`\-\|\[\]]{6,50}$/,
    )
    .required()
    .messages({
      'string.pattern.base':
        'Password must contain at least one number and at least 6 characters long',
    }),
  phone: Joi.string().required(),
  country: Joi.string().required(),
  role: Joi.string().required(),
  rememberMe: Joi.boolean().required(),
}).strict();

export const loginUserValidator = Joi.object({
  email: Joi.string().required(),
  password: Joi.string().required(),
}).strict();

export const resetPasswordValidator = Joi.object({
  password: Joi.string()
    .regex(
      /^(?=.*[A-Za-z])(?=.*\d)[a-zA-Z0-9!@#$%^&*()~¥=_+}{":;'?/>.<,`\-\|\[\]]{6,50}$/,
    )
    .required()
    .messages({
      'string.pattern.base':
        'Password must contain at least one number and at least 6 characters long',
    }),
  confirmPassword: Joi.string()
    .valid(Joi.ref('password'))
    .required()
    .messages({ 'any.only': `Password does not match` }),
}).strict();
