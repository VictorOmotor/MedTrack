import nodemailer from 'nodemailer';
import { config } from '../config/index.js';

export const sendEmail = async (options) => {
  const transporter = nodemailer.createTransport({
    host: config.smtp_host,
    port: config.smtp_port,
    secure: true,
    auth: {
      user: config.smtp_email,
      pass: config.smtp_password,
    },
  });

  // send mail with defined transport object
  const message = {
    from: `${config.from_name}  <${config.from_email}>`,
    to: options.email,
    subject: options.subject,
    text: options.message,
  };

  const info = await transporter.sendMail(message);
};
