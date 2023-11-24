import express from 'express';
import mongoose from 'mongoose';
import morgan from 'morgan';
import { router as userRouter } from './src/routers/user.route.js';
import { globalErrorHandler } from './src/utils/errorHandler.js';
import { config } from './src/config/index.js';
import cookieParser from 'cookie-parser';
import cors from 'cors';
// import path from 'path';

// const __dirname = path.resolve();

const app = express();

app.use(
  cors({
    origin: true,
    credentials: true,
  }),
);
mongoose.set('strictQuery', false);
mongoose
  .connect(config.mongodb_connection_url)
  .then(() => console.log('Database connection established'))
  .catch((e) => console.log('Mongo connection error: ', e.message));

const port = config.port || 3000;

app.use(morgan('tiny'));
app.use(express.json());
app.use(cookieParser());

app.use('/api/user', userRouter);

// app.use(express.static(path.join(__dirname, '/frontend/dist')));

// app.get('*', (req, res) => {
//   res.sendFile(path.join(__dirname, 'frontend', 'dist', 'index.html'));
// });

app.use(globalErrorHandler);

app.listen(port, () => {
  console.log(`Server running on port: ${port}`);
});
